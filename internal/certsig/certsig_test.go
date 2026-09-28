package certsig_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/skarm/kalkan/internal/certsig"
)

// Real Kazakhstan root and NCA RK certificates (production and test) and a test user.
var kalkan = filepath.Join("testdata", "kz", "certificates")

func TestCheckCertificateSignatureAcceptsRealChains(t *testing.T) {
	for _, test := range []struct{ certificate, issuer string }{
		{filepath.Join(kalkan, "prod", "root", "root_gost_2022.crt"), filepath.Join(kalkan, "prod", "root", "root_gost_2022.crt")},
		{filepath.Join(kalkan, "prod", "nca", "nca_gost_2022.crt"), filepath.Join(kalkan, "prod", "root", "root_gost_2022.crt")},
		{filepath.Join(kalkan, "test", "root", "root_test_gost_2022.crt"), filepath.Join(kalkan, "test", "root", "root_test_gost_2022.crt")},
		{filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt"), filepath.Join(kalkan, "test", "root", "root_test_gost_2022.crt")},
		{"testdata/kz/user_gost2022_test.cer", filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")},
	} {
		certificate, issuer := readCertificate(t, test.certificate), readCertificate(t, test.issuer)

		if err := certsig.CheckCertificateSignature(certificate, issuer); err != nil {
			t.Fatalf("%s by %s: CheckCertificateSignature() error = %v", test.certificate, test.issuer, err)
		}

		// Changing any bit of the signed portion or the signature must fail verification.
		for _, tampered := range []*x509.Certificate{
			withCertificateFields(certificate, flipLastBit(certificate.RawTBSCertificate), certificate.Signature),
			withCertificateFields(certificate, certificate.RawTBSCertificate, flipLastBit(certificate.Signature)),
		} {
			if err := certsig.CheckCertificateSignature(tampered, issuer); err == nil || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
				t.Fatalf("%s by %s: CheckCertificateSignature() of a tampered certificate error = %v, want a verification failure",
					test.certificate, test.issuer, err)
			}
		}
	}
}

// Exercise the OCSP signature verifier with a real NCA RK signature.
func TestCheckSignatureAcceptsRealSignature(t *testing.T) {
	certificate := readCertificate(t, "testdata/kz/user_gost2022_test.cer")
	issuer := readCertificate(t, filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt"))
	algorithm := outerSignatureAlgorithm(t, certificate.Raw)

	if err := certsig.CheckSignature(issuer, algorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
		t.Fatalf("CheckSignature() of a real certificate: %v", err)
	}

	for _, tampered := range []*x509.Certificate{
		withCertificateFields(certificate, flipLastBit(certificate.RawTBSCertificate), certificate.Signature),
		withCertificateFields(certificate, certificate.RawTBSCertificate, flipLastBit(certificate.Signature)),
	} {
		if err := certsig.CheckSignature(issuer, algorithm, tampered.RawTBSCertificate, tampered.Signature); err == nil || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
			t.Fatalf("CheckSignature() of a tampered certificate = %v, want a verification failure", err)
		}
	}
}

func TestCheckSignatureRejectsMalformedGostKey(t *testing.T) {
	certificate := readCertificate(t, "testdata/kz/user_gost2022_test.cer")
	issuer := readCertificate(t, filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt"))
	algorithm := outerSignatureAlgorithm(t, certificate.Raw)
	for _, test := range []string{"malformed parameters", "unaligned point", "point outside curve"} {
		t.Run(test, func(t *testing.T) {
			var key struct {
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}
			if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &key); err != nil {
				t.Fatal(err)
			}
			switch test {
			case "malformed parameters":
				key.Algorithm.Parameters = asn1.NullRawValue
			case "unaligned point":
				key.PublicKey.Bytes = bytes.Clone(key.PublicKey.Bytes)
				key.PublicKey.Bytes[len(key.PublicKey.Bytes)-1] &= 0xfe
				key.PublicKey.BitLength--
			case "point outside curve":
				point, err := asn1.Marshal(make([]byte, 128))
				if err != nil {
					t.Fatal(err)
				}
				key.PublicKey = asn1.BitString{Bytes: point, BitLength: 8 * len(point)}
			}
			malformed := *issuer
			var err error
			malformed.RawSubjectPublicKeyInfo, err = asn1.Marshal(key)
			if err != nil {
				t.Fatal(err)
			}
			if err := certsig.CheckSignature(&malformed, algorithm, certificate.RawTBSCertificate, certificate.Signature); err == nil {
				t.Fatal("CheckSignature() accepted a malformed public key")
			}
		})
	}
}

// CheckSignature recognizes crypto/x509 algorithms by OID and delegates to crypto/x509.
// RSASSA-PSS, whose hash is specified in parameters, and unknown algorithms are unsupported.
func TestCheckSignatureDelegatesKnownAlgorithms(t *testing.T) {
	data := []byte("tbsResponseData")
	digest := sha256.Sum256(data)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaSignature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	ecdsaSigner, rsaSigner := selfSigned(t, ecdsaKey, 0), selfSigned(t, rsaKey, 0)
	ecdsaWithSHA256 := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	rsaWithSHA256 := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: asn1.NullRawValue}

	if err := certsig.CheckSignature(ecdsaSigner, ecdsaWithSHA256, data, ecdsaSignature); err != nil {
		t.Fatalf("CheckSignature() of an ECDSA signature error = %v", err)
	}

	if err := certsig.CheckSignature(rsaSigner, rsaWithSHA256, data, rsaSignature); err != nil {
		t.Fatalf("CheckSignature() of an RSA signature error = %v", err)
	}

	if err := certsig.CheckSignature(ecdsaSigner, ecdsaWithSHA256, flipLastBit(data), ecdsaSignature); err == nil {
		t.Fatal("CheckSignature() accepted an ECDSA signature over other data")
	}

	if err := certsig.CheckSignature(rsaSigner, ecdsaWithSHA256, data, rsaSignature); err == nil {
		t.Fatal("CheckSignature() accepted an RSA key for an ECDSA signature")
	}

	for _, algorithm := range []asn1.ObjectIdentifier{{1, 2, 840, 113549, 1, 1, 10}, {1, 2, 3, 4}} {
		if err := certsig.CheckSignature(rsaSigner, pkix.AlgorithmIdentifier{Algorithm: algorithm}, data, rsaSignature); !errors.Is(err, x509.ErrUnsupportedAlgorithm) {
			t.Fatalf("CheckSignature() with algorithm %v error = %v, want %v", algorithm, err, x509.ErrUnsupportedAlgorithm)
		}
	}
}

// outerSignatureAlgorithm reads the signature algorithm of a signed certificate.
func outerSignatureAlgorithm(t *testing.T, raw []byte) pkix.AlgorithmIdentifier {
	t.Helper()

	var signed struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}

	if _, err := asn1.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}

	return signed.Algorithm
}

// An issuer from the same algorithm family but with a different key cannot validate the signature.
func TestCheckCertificateSignatureRejectsAnotherIssuerKey(t *testing.T) {
	for _, test := range []struct{ certificate, issuer string }{
		{filepath.Join(kalkan, "prod", "nca", "nca_gost_2022.crt"), filepath.Join(kalkan, "test", "root", "root_test_gost_2022.crt")},
	} {
		if err := certsig.CheckCertificateSignature(readCertificate(t, test.certificate), readCertificate(t, test.issuer)); err == nil {
			t.Fatalf("%s by %s: CheckCertificateSignature() accepted another issuer key", test.certificate, test.issuer)
		}
	}
}

// Even a valid signature cannot authorize an issuer without certificate-signing permissions.
func TestCheckCertificateSignatureRequiresIssuerRole(t *testing.T) {
	certificate := readCertificate(t, "testdata/kz/user_gost2022_test.cer")
	issuer := readCertificate(t, filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt"))
	if err := certsig.CheckCertificateSignature(certificate, issuer); err != nil {
		t.Fatal(err)
	}

	for _, role := range []struct {
		name                   string
		isCA, basicConstraints bool
		usage                  x509.KeyUsage
	}{
		{"non-CA", false, true, x509.KeyUsageCertSign},
		{"missing basic constraints", true, false, x509.KeyUsageCertSign},
		{"no certificate-signing usage", true, true, x509.KeyUsageCRLSign},
	} {
		t.Run(role.name, func(t *testing.T) {
			invalid := *issuer
			invalid.IsCA, invalid.BasicConstraintsValid, invalid.KeyUsage = role.isCA, role.basicConstraints, role.usage
			var violation x509.ConstraintViolationError
			if err := certsig.CheckCertificateSignature(certificate, &invalid); !errors.As(err, &violation) {
				t.Fatalf("CheckCertificateSignature() = %v, want %T", err, violation)
			}
		})
	}
}

// Kazakhstan's GOST 34.310-2004 cannot be verified and must be rejected as unsupported.
func TestCheckCertificateSignatureRejectsUnsupportedAlgorithms(t *testing.T) {
	for _, test := range []struct{ certificate, issuer string }{
		{filepath.Join(kalkan, "test", "root", "root_gost_test.crt"), filepath.Join(kalkan, "test", "root", "root_gost_test.crt")},
		{filepath.Join(kalkan, "test", "nca", "nca_gost_test.crt"), filepath.Join(kalkan, "test", "root", "root_gost_test.crt")},
	} {
		err := certsig.CheckCertificateSignature(readCertificate(t, test.certificate), readCertificate(t, test.issuer))
		if !errors.Is(err, x509.ErrUnsupportedAlgorithm) {
			t.Fatalf("%s by %s: CheckCertificateSignature() error = %v, want %v", test.certificate, test.issuer, err, x509.ErrUnsupportedAlgorithm)
		}
	}
}

// crypto/x509 verifies its algorithms under its own policy: ECDSA is accepted, while SHA-1
// certificate signatures are rejected.
func TestCheckCertificateSignatureDelegatesKnownAlgorithms(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	authority := selfSigned(t, ecdsaKey, 0)
	if err := certsig.CheckCertificateSignature(authority, authority); err != nil {
		t.Fatalf("CheckCertificateSignature() of an ECDSA certificate error = %v", err)
	}

	tampered := withCertificateFields(authority, authority.RawTBSCertificate, flipLastBit(authority.Signature))
	if err := certsig.CheckCertificateSignature(tampered, authority); err == nil {
		t.Fatal("CheckCertificateSignature() accepted a tampered ECDSA certificate")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	legacy := selfSigned(t, rsaKey, x509.SHA1WithRSA)

	var insecure x509.InsecureAlgorithmError
	if err := certsig.CheckCertificateSignature(legacy, legacy); !errors.As(err, &insecure) {
		t.Fatalf("CheckCertificateSignature() of a SHA-1 certificate error = %v, want %T", err, insecure)
	}
}

func selfSigned(t *testing.T, key crypto.Signer, algorithm x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Authority"}, SignatureAlgorithm: algorithm,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return certificate
}

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(decodeFixture(t, data, "CERTIFICATE"))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}

	return certificate
}

// decodeFixture reads the DER and PEM encodings used by the checked-in fixtures.
func decodeFixture(t *testing.T, data []byte, pemType string) []byte {
	t.Helper()

	if block, rest := pem.Decode(data); block != nil {
		if block.Type != pemType || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatalf("invalid PEM %s fixture", pemType)
		}
		return block.Bytes
	}
	return data
}

func withCertificateFields(certificate *x509.Certificate, tbs, signature []byte) *x509.Certificate {
	tampered := *certificate
	tampered.RawTBSCertificate, tampered.Signature = tbs, signature

	return &tampered
}

func flipLastBit(data []byte) []byte {
	flipped := slices.Clone(data)
	flipped[len(flipped)-1] ^= 1

	return flipped
}
