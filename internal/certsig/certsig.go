// Package certsig verifies certificate and OCSP signatures with the issuer's
// key.
// It supports Kazakhstan's 256-bit and 512-bit ST RK GOST R 34.10-2015
// profiles, which crypto/x509 does not implement.
//
// Concurrent calls can share certificates and input slices if callers keep
// them unchanged.
//
// crypto/x509 verifies its supported algorithms under its SHA-1 and MD5
// policy.
// The package returns x509.ErrUnsupportedAlgorithm for algorithms that it
// cannot verify.
// These include legacy Kazakhstan GOST 34.310-2004.
package certsig

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// CheckCertificateSignature verifies the certificate signature and the
// issuer's authority to sign certificates.
// It follows [x509.Certificate.CheckSignatureFrom].
func CheckCertificateSignature(certificate, issuer *x509.Certificate) error {
	if certificate == nil || issuer == nil {
		return errors.New("certsig: missing certificate or issuer")
	}

	if certificate.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return certificate.CheckSignatureFrom(issuer)
	}

	// crypto/x509 already checked that both certificate algorithm fields match.
	var signed struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(certificate.Raw, &signed); err != nil || len(rest) != 0 {
		return errors.New("certsig: malformed certificate")
	}

	if !signed.Algorithm.Algorithm.Equal(oidSignatureKazakhGost2015Digest256) &&
		!signed.Algorithm.Algorithm.Equal(oidSignatureKazakhGost2015Digest512) {
		return certificate.CheckSignatureFrom(issuer)
	}

	if !matchesASN1Encoding(certificate.Raw, signed) || signed.Signature.BitLength%8 != 0 ||
		!bytes.Equal(signed.TBS.FullBytes, certificate.RawTBSCertificate) ||
		!bytes.Equal(signed.Signature.Bytes, certificate.Signature) || !gostCertificateAlgorithmsMatch(signed.TBS, signed.Algorithm) {
		return errors.New("certsig: malformed GOST certificate")
	}

	// Check crypto/x509's issuer constraints before verification of the custom
	// algorithm.
	if issuer.Version == 3 && !issuer.BasicConstraintsValid || issuer.BasicConstraintsValid && !issuer.IsCA {
		return x509.ConstraintViolationError{}
	}

	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}

	return CheckSignature(issuer, signed.Algorithm, certificate.RawTBSCertificate, certificate.Signature)
}

// CheckSignature verifies signature over signed with algorithm and signer.
// Like [x509.Certificate.CheckSignature], it does not check the signer's role.
// The caller must check that role for OCSP responses under RFC 6960, section 4.2.1.
//
// The supported crypto/x509 algorithms are RSA PKCS #1 v1.5, ECDSA, and Ed25519.
// The function returns x509.ErrUnsupportedAlgorithm for RSASSA-PSS, which
// specifies its hash in parameters.
func CheckSignature(signer *x509.Certificate, algorithm pkix.AlgorithmIdentifier, signed, signature []byte) error {
	if signer == nil {
		return errors.New("certsig: missing signer")
	}

	if algorithm.Algorithm.Equal(oidSignatureKazakhGost2015Digest256) || algorithm.Algorithm.Equal(oidSignatureKazakhGost2015Digest512) {
		if !validGostSignatureParameters(algorithm.Parameters) {
			return errors.New("certsig: malformed GOST signature parameters")
		}

		return verifyKazakhGost2015(signer, algorithm.Algorithm, signed, signature)
	}

	known := x509Algorithm(algorithm.Algorithm)
	if known == x509.UnknownSignatureAlgorithm {
		return x509.ErrUnsupportedAlgorithm
	}

	return signer.CheckSignature(known, signed, signature)
}

// matchesASN1Encoding reports whether encoded matches the ASN.1 encoding of
// value. ASN.1 conversion preserves opaque TBS and parameter RawValues but
// exposes extra fields that encoding/asn1 ignores in a struct SEQUENCE.
func matchesASN1Encoding(encoded []byte, value any) bool {
	canonical, err := asn1.Marshal(value)
	return err == nil && bytes.Equal(encoded, canonical)
}

func validGostSignatureParameters(parameters asn1.RawValue) bool {
	if parameters.Class == 0 && parameters.Tag == 0 && !parameters.IsCompound && len(parameters.Bytes) == 0 && len(parameters.FullBytes) == 0 {
		return true
	}

	return matchesASN1Encoding(asn1.NullBytes, parameters)
}

// gostCertificateAlgorithmsMatch reports whether tbs and outer specify the same
// certificate signature algorithm. x509 parsed the remaining fields, so this
// check inspects only the signed TBS prefix. SerialNumber stays opaque to
// support legacy negative serial numbers.
func gostCertificateAlgorithmsMatch(tbs asn1.RawValue, outer pkix.AlgorithmIdentifier) bool {
	if tbs.Class != asn1.ClassUniversal || tbs.Tag != asn1.TagSequence || !tbs.IsCompound {
		return false
	}

	var prefix struct {
		Version      int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber asn1.RawValue
		Algorithm    asn1.RawValue
	}

	if rest, err := asn1.Unmarshal(tbs.FullBytes, &prefix); err != nil || len(rest) != 0 ||
		prefix.SerialNumber.Class != asn1.ClassUniversal || prefix.SerialNumber.Tag != asn1.TagInteger || prefix.SerialNumber.IsCompound {
		return false
	}

	return matchesASN1Encoding(prefix.Algorithm.FullBytes, outer)
}

// x509Algorithm returns the crypto/x509 signature algorithm for this OID (RFC 3279, 5758, and 8410),
// or x509.UnknownSignatureAlgorithm.
func x509Algorithm(algorithm asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}):
		return x509.SHA1WithRSA
	case algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}):
		return x509.SHA256WithRSA
	case algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}):
		return x509.SHA384WithRSA
	case algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}):
		return x509.SHA512WithRSA
	case algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}):
		return x509.ECDSAWithSHA1
	case algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}):
		return x509.ECDSAWithSHA256
	case algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}):
		return x509.ECDSAWithSHA384
	case algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}):
		return x509.ECDSAWithSHA512
	case algorithm.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}):
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}
