// Package certsig verifies certificate and OCSP signatures using the issuer's key, including
// Kazakhstan's 512-bit ST RK GOST R 34.10-2015 (NCA RK 2022), absent from crypto/x509.
//
// Algorithms known to crypto/x509 are verified by crypto/x509 with its SHA-1 and MD5 policy.
// Signatures that cannot be verified are rejected with x509.ErrUnsupportedAlgorithm because
// authenticity has not been established. This includes legacy Kazakhstan GOST 34.310-2004
// and 256-bit ST RK GOST R 34.10-2015.
package certsig

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// CheckCertificateSignature verifies that certificate is signed by issuer and that issuer
// is authorized to sign certificates, like (*x509.Certificate).CheckSignatureFrom.
func CheckCertificateSignature(certificate, issuer *x509.Certificate) error {
	if certificate.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return certificate.CheckSignatureFrom(issuer)
	}

	// crypto/x509 has already checked that both certificate algorithm fields match.
	var signed struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(certificate.Raw, &signed); err != nil || len(rest) != 0 {
		return errors.New("certsig: malformed certificate")
	}

	if !signed.Algorithm.Algorithm.Equal(oidSignatureKazakhGost2015Digest512) {
		return certificate.CheckSignatureFrom(issuer)
	}

	// Match crypto/x509's issuer constraints before verifying the custom algorithm.
	if issuer.Version == 3 && !issuer.BasicConstraintsValid || issuer.BasicConstraintsValid && !issuer.IsCA {
		return x509.ConstraintViolationError{}
	}

	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}

	return verifyKazakhGost2015(issuer, certificate.RawTBSCertificate, certificate.Signature)
}

// CheckSignature verifies signature over signed using algorithm and signer, like
// (*x509.Certificate).CheckSignature; it does not check signer's role. This verifies OCSP
// responses (RFC 6960, 4.2.1), signed by a CA or a responder delegated through id-kp-OCSPSigning;
// the caller checks the signer's role. Supported crypto/x509 algorithms are RSA PKCS #1 v1.5,
// ECDSA, and Ed25519. RSASSA-PSS, whose hash is specified in its parameters, is rejected with
// x509.ErrUnsupportedAlgorithm.
func CheckSignature(signer *x509.Certificate, algorithm pkix.AlgorithmIdentifier, signed, signature []byte) error {
	if algorithm.Algorithm.Equal(oidSignatureKazakhGost2015Digest512) {
		return verifyKazakhGost2015(signer, signed, signature)
	}

	known := x509Algorithm(algorithm.Algorithm)
	if known == x509.UnknownSignatureAlgorithm {
		return x509.ErrUnsupportedAlgorithm
	}

	return signer.CheckSignature(known, signed, signature)
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
