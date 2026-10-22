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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"hash"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/skarm/kalkan/internal/certsig"
	"github.com/skarm/kalkan/internal/certsig/internal/gogost/gost3410"
	"github.com/skarm/kalkan/internal/certsig/internal/gogost/gost34112012256"
	"github.com/skarm/kalkan/internal/certsig/internal/gogost/gost34112012512"
)

// Real Kazakhstan root and NCA RK certificates (production and test) and a test user.
var kalkan = filepath.Join("testdata", "kz", "certificates")

// Synthetic 256-bit certificates and signatures were generated and verified independently
// with KalkanCrypt Java 0.7.5. The OCSP package shares these public fixtures.
const gost256Fixtures = "../../testdata/ocsp/gost2015_256/"

func TestCheckCertificateSignatureAcceptsGostChains(t *testing.T) {
	for _, test := range []struct{ certificate, issuer string }{
		{filepath.Join(kalkan, "prod", "root", "root_gost_2022.crt"), filepath.Join(kalkan, "prod", "root", "root_gost_2022.crt")},
		{filepath.Join(kalkan, "prod", "nca", "nca_gost_2022.crt"), filepath.Join(kalkan, "prod", "root", "root_gost_2022.crt")},
		{filepath.Join(kalkan, "test", "root", "root_test_gost_2022.crt"), filepath.Join(kalkan, "test", "root", "root_test_gost_2022.crt")},
		{filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt"), filepath.Join(kalkan, "test", "root", "root_test_gost_2022.crt")},
		{"testdata/kz/user_gost2022_test.cer", filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")},
		{gost256Fixtures + "gost256-ca.der", gost256Fixtures + "gost256-ca.der"},
		{gost256Fixtures + "gost256-leaf.der", gost256Fixtures + "gost256-ca.der"},
		{gost256Fixtures + "gost256-delegate.der", gost256Fixtures + "gost256-ca.der"},
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

func TestCheckSignatureAcceptsGost256SDKSignature(t *testing.T) {
	issuer := readCertificate(t, gost256Fixtures+"gost256-ca.der")
	algorithm := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 1}}
	message := readFixture(t, gost256Fixtures+"gost256-message.bin")
	signature := readFixture(t, gost256Fixtures+"gost256-message.sig")
	if !bytes.Equal(issuer.RawSubjectPublicKeyInfo, readFixture(t, gost256Fixtures+"gost256-spki.der")) {
		t.Fatal("SDK message signing key differs from the CA public key")
	}
	h := gost34112012256.New()
	h.Write(message)
	if got, want := h.Sum(nil), readFixture(t, gost256Fixtures+"gost256-message.hash"); !bytes.Equal(got, want) {
		t.Fatalf("Streebog-256 = %x, want SDK digest %x", got, want)
	}
	if err := certsig.CheckSignature(issuer, algorithm, message, signature); err != nil {
		t.Fatalf("CheckSignature() of an SDK signature: %v", err)
	}

	for _, test := range []struct {
		name      string
		signer    *x509.Certificate
		algorithm pkix.AlgorithmIdentifier
		message   []byte
		signature []byte
	}{
		{"changed message", issuer, algorithm, flipLastBit(message), signature},
		{"changed signature", issuer, algorithm, message, flipLastBit(signature)},
		{"short signature", issuer, algorithm, message, signature[:63]},
		{"long signature", issuer, algorithm, message, append(bytes.Clone(signature), 0)},
		{"zero signature", issuer, algorithm, message, make([]byte, 64)},
		{"different key", readCertificate(t, gost256Fixtures+"gost256-delegate.der"), algorithm, message, signature},
		{"512-bit key", readCertificate(t, filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")), algorithm, message, signature},
		{"512-bit algorithm", issuer, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 2}}, message, signature},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := certsig.CheckSignature(test.signer, test.algorithm, test.message, test.signature); err == nil || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
				t.Fatalf("CheckSignature() = %v, want a verification failure", err)
			}
		})
	}
}

// TestCheckSignatureAcceptsRealSignature checks OCSP signature verification
// with a real NCA RK signature.
//
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
	for _, fixture := range []struct{ name, certificate, issuer string }{
		{"256", gost256Fixtures + "gost256-leaf.der", gost256Fixtures + "gost256-ca.der"},
		{"512", "testdata/kz/user_gost2022_test.cer", filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			certificate, issuer := readCertificate(t, fixture.certificate), readCertificate(t, fixture.issuer)
			algorithm := outerSignatureAlgorithm(t, certificate.Raw)
			if err := certsig.CheckSignature(issuer, algorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
				t.Fatalf("valid signature: %v", err)
			}
			for _, test := range []string{"malformed parameters", "unaligned point", "point outside curve", "short point", "long point", "unknown curve", "wrong key algorithm", "wrong digest", "unknown digest", "malformed digest", "extra parameters"} {
				t.Run(test, func(t *testing.T) {
					var key gostSubjectPublicKeyInfo
					if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &key); err != nil {
						t.Fatal(err)
					}
					var point []byte
					if _, err := asn1.Unmarshal(key.PublicKey.Bytes, &point); err != nil {
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
						point = make([]byte, len(point))
					case "short point":
						point = point[:len(point)-1]
					case "long point":
						point = append(bytes.Clone(point), 0)
					case "unknown curve":
						key.Algorithm.Parameters.FullBytes = marshalFixture(t, struct{ Curve asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 3, 4}})
					case "wrong key algorithm":
						key.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
					case "wrong digest", "unknown digest", "malformed digest", "extra parameters":
						var parameters struct {
							Curve  asn1.ObjectIdentifier
							Digest asn1.ObjectIdentifier `asn1:"optional"`
						}
						if _, err := asn1.Unmarshal(key.Algorithm.Parameters.FullBytes, &parameters); err != nil {
							t.Fatal(err)
						}
						switch test {
						case "wrong digest":
							parameters.Digest = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 3, 2}
							if fixture.name == "256" {
								parameters.Digest = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 3, 3}
							}
							key.Algorithm.Parameters.FullBytes = marshalFixture(t, parameters)
						case "unknown digest":
							parameters.Digest = asn1.ObjectIdentifier{1, 2, 3, 4}
							key.Algorithm.Parameters.FullBytes = marshalFixture(t, parameters)
						case "malformed digest":
							key.Algorithm.Parameters.FullBytes = marshalFixture(t, struct {
								Curve  asn1.ObjectIdentifier
								Digest asn1.RawValue
							}{parameters.Curve, asn1.NullRawValue})
						case "extra parameters":
							key.Algorithm.Parameters.FullBytes = marshalFixture(t, struct {
								Curve, Digest asn1.ObjectIdentifier
								Extra         int
							}{parameters.Curve, parameters.Digest, 1})
						}
					}
					if test == "point outside curve" || test == "short point" || test == "long point" {
						encoded := marshalFixture(t, point)
						key.PublicKey = asn1.BitString{Bytes: encoded, BitLength: 8 * len(encoded)}
					}
					malformed := *issuer
					malformed.RawSubjectPublicKeyInfo = marshalFixture(t, key)
					err := certsig.CheckSignature(&malformed, algorithm, certificate.RawTBSCertificate, certificate.Signature)
					if err == nil {
						t.Fatal("CheckSignature() accepted a malformed public key")
					}
					if (test == "unknown curve" || test == "wrong digest" || test == "unknown digest") && !errors.Is(err, x509.ErrUnsupportedAlgorithm) {
						t.Fatalf("%s: %v, want ErrUnsupportedAlgorithm", test, err)
					}
				})
			}
		})
	}
}

// TestCheckSignatureAcceptsGostKeyWithoutDigestParameter checks GOST keys
// without optional digest parameters.
//
// Both SDK profiles include the matching digest OID. An absent digest OID is
// also valid because the signature OID identifies the hash function.
func TestCheckSignatureAcceptsGostKeyWithoutDigestParameter(t *testing.T) {
	for _, fixture := range []struct{ name, certificate, issuer string }{
		{"256", gost256Fixtures + "gost256-leaf.der", gost256Fixtures + "gost256-ca.der"},
		{"512", "testdata/kz/user_gost2022_test.cer", filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			certificate, issuer := readCertificate(t, fixture.certificate), readCertificate(t, fixture.issuer)
			var key gostSubjectPublicKeyInfo
			if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &key); err != nil {
				t.Fatal(err)
			}
			var parameters struct{ Curve asn1.ObjectIdentifier }
			if _, err := asn1.Unmarshal(key.Algorithm.Parameters.FullBytes, &parameters); err != nil {
				t.Fatal(err)
			}
			key.Algorithm.Parameters.FullBytes = marshalFixture(t, parameters)
			signer := *issuer
			signer.RawSubjectPublicKeyInfo = marshalFixture(t, key)
			if err := certsig.CheckSignature(&signer, outerSignatureAlgorithm(t, certificate.Raw), certificate.RawTBSCertificate, certificate.Signature); err != nil {
				t.Fatalf("key without optional digest: %v", err)
			}
		})
	}
}

// TestCheckSignatureDelegatesKnownAlgorithms checks supported crypto/x509
// algorithms and rejects unsupported algorithms.
//
// CheckSignature recognizes crypto/x509 algorithms by OID and delegates to
// crypto/x509. RSASSA-PSS, whose hash is specified in parameters, and unknown
// algorithms are unsupported.
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
func outerSignatureAlgorithm(t testing.TB, raw []byte) pkix.AlgorithmIdentifier {
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

// TestCheckCertificateSignatureRejectsAnotherIssuerKey checks that verification
// rejects a different issuer key.
//
// An issuer from the same algorithm family but with a different key cannot
// validate the signature.
func TestCheckCertificateSignatureRejectsAnotherIssuerKey(t *testing.T) {
	for _, test := range []struct{ certificate, issuer string }{
		{filepath.Join(kalkan, "prod", "nca", "nca_gost_2022.crt"), filepath.Join(kalkan, "test", "root", "root_test_gost_2022.crt")},
	} {
		if err := certsig.CheckCertificateSignature(readCertificate(t, test.certificate), readCertificate(t, test.issuer)); err == nil {
			t.Fatalf("%s by %s: CheckCertificateSignature() accepted another issuer key", test.certificate, test.issuer)
		}
	}
}

// TestCheckCertificateSignatureRequiresIssuerRole checks the issuer permission
// to sign certificates.
//
// Even a valid signature cannot authorize an issuer without certificate-signing
// permissions.
func TestCheckCertificateSignatureRequiresIssuerRole(t *testing.T) {
	for _, fixture := range []struct{ name, certificate, issuer string }{
		{"256", gost256Fixtures + "gost256-leaf.der", gost256Fixtures + "gost256-ca.der"},
		{"512", "testdata/kz/user_gost2022_test.cer", filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			certificate, issuer := readCertificate(t, fixture.certificate), readCertificate(t, fixture.issuer)
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
		})
	}
}

// TestCheckCertificateSignatureRejectsUnsupportedAlgorithms checks rejection of
// unsupported certificate signature algorithms.
//
// Kazakhstan's GOST 34.310-2004 cannot be verified and must be rejected as
// unsupported.
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

// TestCheckCertificateSignatureDelegatesKnownAlgorithms checks certificate
// signatures under crypto/x509 policy.
//
// crypto/x509 verifies its algorithms under its own policy: ECDSA is accepted,
// while SHA-1 certificate signatures are rejected.
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

func TestVerifyDigestHandlesEqualPointCoordinates(t *testing.T) {
	for _, curve := range []*gost3410.Curve{gost3410.CurveIdtc26gost341012256paramSetA(), gost3410.CurveIdtc26gost341012512paramSetA()} {
		t.Run(curve.Name, func(t *testing.T) {
			doubledX, _, err := curve.Exp(big.NewInt(2), curve.X, curve.Y)
			if err != nil {
				t.Fatal(err)
			}

			for _, test := range []struct {
				name  string
				r     *big.Int
				valid bool
			}{
				{
					name:  "equal points must be doubled",
					r:     new(big.Int).Mod(doubledX, curve.Q),
					valid: true,
				},
				{
					name: "opposite points sum to infinity",
					r:    new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Lsh(curve.X, 1)), curve.P),
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					r := new(big.Int).Mod(test.r, curve.Q)
					d := new(big.Int).ModInverse(r, curve.Q)
					if d == nil {
						t.Fatal("test signature r has no modular inverse")
					}
					if test.valid {
						// With digest e=1, nonce k=2 and d=-1/r, the signing
						// equation s=r*d+k*e gives s=1. Verification adds G+G.
						d.Neg(d).Mod(d, curve.Q)
					}
					x, y, err := curve.Exp(d, curve.X, curve.Y)
					if err != nil {
						t.Fatal(err)
					}
					public := gost3410.PublicKey{C: curve, X: x, Y: y}
					signature := make([]byte, 2*curve.PointSize())
					signature[curve.PointSize()-1] = 1
					r.FillBytes(signature[curve.PointSize():])
					// For d=1/r, the same s=1 instead adds G+(-G), which
					// cannot produce a valid signature for any nonzero r.
					valid, err := public.VerifyDigest([]byte{1}, signature)
					if err != nil || valid != test.valid {
						t.Fatalf("VerifyDigest() = %t, %v; want %t", valid, err, test.valid)
					}
				})
			}
		})
	}
}

func TestCurveEqualHandlesOptionalParameters(t *testing.T) {
	base := gost3410.CurveIdtc26gost341012512paramSetA()
	newCurve := func(e, d *big.Int) *gost3410.Curve {
		t.Helper()
		curve, err := gost3410.NewCurve(base.P, base.Q, base.A, base.B, base.X, base.Y, e, d, nil)
		if err != nil {
			t.Fatal(err)
		}
		return curve
	}
	plain := newCurve(nil, nil)
	withOptional := newCurve(big.NewInt(1), big.NewInt(2))
	for _, test := range []struct {
		name        string
		left, right *gost3410.Curve
		want        bool
	}{
		{"both omit parameters", plain, newCurve(nil, nil), true},
		{"same optional parameters", withOptional, newCurve(big.NewInt(1), big.NewInt(2)), true},
		{"only right includes parameters", plain, withOptional, false},
		{"only left includes parameters", withOptional, plain, false},
		{"different optional E", withOptional, newCurve(big.NewInt(3), big.NewInt(2)), false},
		{"different optional D", withOptional, newCurve(big.NewInt(1), big.NewInt(3)), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.left.Equal(test.right); got != test.want {
				t.Fatalf("Equal() = %t; want %t", got, test.want)
			}
		})
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

func readCertificate(t testing.TB, path string) *x509.Certificate {
	t.Helper()

	certificate, err := x509.ParseCertificate(decodeFixture(t, readFixture(t, path), "CERTIFICATE"))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}

	return certificate
}

func readFixture(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// decodeFixture reads the DER and PEM encodings used by the checked-in fixtures.
func decodeFixture(t testing.TB, data []byte, pemType string) []byte {
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

type gostSubjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func marshalFixture(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestCurveSubgroupMembership checks subgroup membership with independently
// calculated curve points.
//
// Literal on-curve points were derived with independent affine arithmetic. The
// mixed points G+T and G+U have large order, so rejecting only small-order keys
// is insufficient.
func TestCurveSubgroupMembership(t *testing.T) {
	curve := gost3410.CurveIdtc26gost341012256paramSetA()
	for _, test := range []struct {
		name, x, y string
		want       bool
	}{
		{"generator", "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28", "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C", true},
		{"order2", "0100FE73F595FF158E974B44D478D9588744FE5C192AC47EA63075DCE7A14AAA", "0000000000000000000000000000000000000000000000000000000000000000", false},
		{"order4", "7F7F80C60535007538B45A5D95C39353BC5D80D1F36A9DC0ACE7C5118C2F5977", "7E7E82520F9F015FAA1D0F18C14AB9FB35188275DA3FD94206B74F34A48E0ECD", false},
		{"mixed_order2", "18476B1AF2E5CECDC380E4C91D2A3A5C2B6C0788066615E2B4E9A63246463E96", "4CFA952E3B48A1409977E07FABA396136986D7E8EDC05C336154375BE5070030", false},
		{"mixed_order4", "DDB921090CC4903145EC19C1E5A683137E548E895E189C8F32B7E8D45A953AE1", "266B0860F3C4DA7273AB5C51D5DFD1B1FD3971404EEB66D9B296EB3D7E342D8A", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			x, y := fixtureInteger(t, test.x), fixtureInteger(t, test.y)
			if !curve.Contains(x, y) {
				t.Fatal("independent fixture must lie on the curve")
			}
			if got := curve.IsInSubgroup(x, y); got != test.want {
				t.Fatalf("IsInSubgroup() = %t, want %t", got, test.want)
			}
		})
	}
	for _, c := range []*gost3410.Curve{curve, gost3410.CurveIdtc26gost341012512paramSetA()} {
		t.Run(c.Name+"/bounds", func(t *testing.T) {
			if !c.IsInSubgroup(c.X, c.Y) {
				t.Fatal("base point must be in the subgroup")
			}
			for _, point := range [][2]*big.Int{
				{nil, c.Y},
				{c.X, nil},
				{big.NewInt(-1), c.Y},
				{c.X, big.NewInt(-1)},
				{new(big.Int).Add(c.X, c.P), c.Y},
				{c.X, new(big.Int).Add(c.Y, c.P)},
				{big.NewInt(0), big.NewInt(0)},
			} {
				if c.IsInSubgroup(point[0], point[1]) {
					t.Fatalf("IsInSubgroup(%v, %v) accepted invalid coordinates", point[0], point[1])
				}
			}
		})
	}
}

func TestCurveExpHandlesInfinity(t *testing.T) {
	curve := gost3410.CurveIdtc26gost341012256paramSetA()
	x := fixtureInteger(t, "7F7F80C60535007538B45A5D95C39353BC5D80D1F36A9DC0ACE7C5118C2F5977")
	y := fixtureInteger(t, "7E7E82520F9F015FAA1D0F18C14AB9FB35188275DA3FD94206B74F34A48E0ECD")
	tx := fixtureInteger(t, "0100FE73F595FF158E974B44D478D9588744FE5C192AC47EA63075DCE7A14AAA")
	for _, test := range []struct {
		degree int64
		x, y   *big.Int
	}{
		{-1, nil, nil},
		{0, nil, nil},
		{1, x, y},
		{2, tx, big.NewInt(0)},
		{3, x, new(big.Int).Sub(curve.P, y)},
		{4, nil, nil},
		{5, x, y},
		{6, tx, big.NewInt(0)},
	} {
		gotX, gotY, err := curve.Exp(big.NewInt(test.degree), x, y)
		if test.x == nil {
			if err == nil || gotX != nil || gotY != nil {
				t.Fatalf("Exp(%d) = (%v, %v), %v; want no finite point", test.degree, gotX, gotY, err)
			}
		} else if err != nil || gotX.Cmp(test.x) != 0 || gotY.Cmp(test.y) != 0 {
			t.Fatalf("Exp(%d) = (%v, %v), %v; want (%v, %v)", test.degree, gotX, gotY, err, test.x, test.y)
		}
	}
	if x.Cmp(fixtureInteger(t, "7F7F80C60535007538B45A5D95C39353BC5D80D1F36A9DC0ACE7C5118C2F5977")) != 0 ||
		y.Cmp(fixtureInteger(t, "7E7E82520F9F015FAA1D0F18C14AB9FB35188275DA3FD94206B74F34A48E0ECD")) != 0 {
		t.Fatal("Exp mutated its input point")
	}
}

// TestCurveExpAroundSubgroupOrder checks scalar multiplication near the
// subgroup order.
//
// Exercise scalar multiplication around the subgroup order for both profiles,
// including recovery from an intermediate point at infinity.
func TestCurveExpAroundSubgroupOrder(t *testing.T) {
	for _, curve := range []*gost3410.Curve{
		gost3410.CurveIdtc26gost341012256paramSetA(),
		gost3410.CurveIdtc26gost341012512paramSetA(),
	} {
		t.Run(curve.Name, func(t *testing.T) {
			twiceQ := new(big.Int).Lsh(curve.Q, 1)
			for _, test := range []struct {
				name         string
				degree, x, y *big.Int
			}{
				{"q-1", new(big.Int).Sub(curve.Q, big.NewInt(1)), curve.X, new(big.Int).Sub(curve.P, curve.Y)},
				{"q", new(big.Int).Set(curve.Q), nil, nil},
				{"q+1", new(big.Int).Add(curve.Q, big.NewInt(1)), curve.X, curve.Y},
				{"2q", twiceQ, nil, nil},
				{"2q+1", new(big.Int).Add(twiceQ, big.NewInt(1)), curve.X, curve.Y},
			} {
				t.Run(test.name, func(t *testing.T) {
					x, y, err := curve.Exp(test.degree, curve.X, curve.Y)
					if test.x == nil {
						if err == nil || x != nil || y != nil {
							t.Fatalf("Exp(%s) = (%v, %v), %v; want infinity", test.name, x, y, err)
						}
					} else if err != nil || x.Cmp(test.x) != 0 || y.Cmp(test.y) != 0 {
						t.Fatalf("Exp(%s) = (%v, %v), %v; want (%v, %v)", test.name, x, y, err, test.x, test.y)
					}
				})
			}
		})
	}
}

func fixtureInteger(t *testing.T, value string) *big.Int {
	t.Helper()
	integer, ok := new(big.Int).SetString(value, 16)
	if !ok {
		t.Fatalf("invalid hexadecimal integer %q", value)
	}
	return integer
}

// TestCheckSignatureRejectsGost256KeyOutsideSubgroup checks rejection of GOST
// keys outside the required subgroup.
//
// A mixed-order key can satisfy the signature equation outside the required
// subgroup. These independent vectors detect removal of the subgroup check.
// They test more than rejection of an invalid signature.
func TestCheckSignatureRejectsGost256KeyOutsideSubgroup(t *testing.T) {
	issuer := readCertificate(t, gost256Fixtures+"gost256-ca.der")
	algorithm := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 1}}
	message := readFixture(t, gost256Fixtures+"gost256-message.bin")
	digest := readFixture(t, gost256Fixtures+"gost256-message.hash")
	// d=1, k=1, r=Gx mod q, s=r+e mod q. The verification coefficient of
	// the public key is divisible by 4, eliminating its torsion component.
	signature := decodeHexFixture(t, "5a91c19b5324fa085c363702d7f5d945bbb21257422309880d2ce8a54384e311968c3398244f26e9d80856dd501c42cfe6285c3c9a80af30f2d2cd834c132325")
	for _, test := range []struct{ name, point string }{
		{"mixed_order2", "963e464632a6e9b4e215660688076c2b5c3a2a1dc9e480c3cdcee5f21a6b4718300007e55b375461335cc0ede8d786691396a3ab7fe0779940a1483b2e95fa4c"},
		{"mixed_order4", "e13a955ad4e8b7328f9c185e898e547e1383a6e5c119ec453190c40c0921b9dd8a2d347e3deb96b2d966eb4e407139fdb1d1dfd5515cab7372dac4f360086b26"},
	} {
		t.Run(test.name, func(t *testing.T) {
			point := decodeHexFixture(t, test.point)
			publicKey, err := gost3410.NewPublicKeyLE(gost3410.CurveIdtc26gost341012256paramSetA(), point)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := (gost3410.PublicKeyReverseDigestAndSignature{Pub: publicKey}).VerifyDigest(digest, signature)
			if err != nil || !valid {
				t.Fatalf("signature equation control = %t, %v; want true", valid, err)
			}
			var key gostSubjectPublicKeyInfo
			if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &key); err != nil {
				t.Fatal(err)
			}
			encoded := marshalFixture(t, point)
			key.PublicKey = asn1.BitString{Bytes: encoded, BitLength: 8 * len(encoded)}
			invalid := *issuer
			invalid.RawSubjectPublicKeyInfo = marshalFixture(t, key)
			if err := certsig.CheckSignature(&invalid, algorithm, message, signature); err == nil || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
				t.Fatalf("CheckSignature() = %v, want rejection of a key outside the subgroup", err)
			}
		})
	}
}

func decodeHexFixture(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// TestCurveFactoriesKeepMutableParametersIndependent checks that curves do not
// share mutable parameters.
//
// Factory results expose mutable integers, but mutating one result must not
// change another curve or the constants used by subsequent verifications.
func TestCurveFactoriesKeepMutableParametersIndependent(t *testing.T) {
	for _, factory := range []func() *gost3410.Curve{
		gost3410.CurveIdtc26gost341012256paramSetA,
		gost3410.CurveIdtc26gost341012512paramSetA,
	} {
		for _, parameter := range []struct {
			name string
			get  func(*gost3410.Curve) *big.Int
		}{
			{"E", func(c *gost3410.Curve) *big.Int { return c.E }},
			{"D", func(c *gost3410.Curve) *big.Int { return c.D }},
			{"cofactor", func(c *gost3410.Curve) *big.Int { return c.Co }},
		} {
			t.Run(factory().Name+"/"+parameter.name, func(t *testing.T) {
				left, right := factory(), factory()
				value := parameter.get(left)
				if value == nil {
					return
				}
				original := new(big.Int).Set(value)
				// Restore shared upstream state even when this regression fails.
				t.Cleanup(func() { value.Set(original) })
				value.Add(value, big.NewInt(1))
				for _, other := range []*gost3410.Curve{right, factory()} {
					if got := parameter.get(other); got == nil || got.Cmp(original) != 0 {
						t.Fatalf("mutating one curve changed another curve's %s: got %v, want %v", parameter.name, got, original)
					}
				}
			})
		}
	}
}

// TestNewCurveCopiesAllParameters checks that curve constructors copy mutable
// parameters.
//
// Constructor callers may retain their parameter integers. Changing them after
// construction must not affect a curve being used by another goroutine.
func TestNewCurveCopiesAllParameters(t *testing.T) {
	for _, factory := range []func() *gost3410.Curve{
		gost3410.CurveIdtc26gost341012256paramSetA,
		gost3410.CurveIdtc26gost341012512paramSetA,
	} {
		t.Run(factory().Name, func(t *testing.T) {
			parameters := factory()
			curve, err := gost3410.NewCurve(parameters.P, parameters.Q, parameters.A, parameters.B,
				parameters.X, parameters.Y, parameters.E, parameters.D, parameters.Co)
			if err != nil {
				t.Fatal(err)
			}
			expected := factory()
			for _, value := range []*big.Int{
				parameters.P, parameters.Q, parameters.A, parameters.B,
				parameters.X, parameters.Y, parameters.E, parameters.D, parameters.Co,
			} {
				if value != nil {
					value.SetInt64(0)
				}
			}
			if !curve.Equal(expected) {
				t.Fatal("NewCurve retained mutable caller-owned parameters")
			}
			if !curve.IsInSubgroup(curve.X, curve.Y) {
				t.Fatal("mutating constructor inputs changed subgroup validation")
			}
		})
	}
}

// TestConcurrentGostVerification checks concurrent verification with shared
// inputs and both GOST profiles.
//
// All workers share the same parsed certificates, public keys and input slices.
// Both profiles run together so the race detector observes their shared
// constants.
func TestConcurrentGostVerification(t *testing.T) {
	type fixture struct {
		name                                                       string
		issuer, certificate, invalidCertificate                    *x509.Certificate
		algorithm                                                  pkix.AlgorithmIdentifier
		public                                                     *gost3410.PublicKey
		digest, signature, invalidSignature                        []byte
		issuerBefore, certificateBefore, pointBefore, digestBefore []byte
		expectedCurve                                              *gost3410.Curve
	}
	fixtures := make([]fixture, 0, 2)
	for _, profile := range []struct {
		name, certificate, issuer string
		newCurve                  func() *gost3410.Curve
		newHash                   func() hash.Hash
	}{
		{"256", gost256Fixtures + "gost256-leaf.der", gost256Fixtures + "gost256-ca.der", gost3410.CurveIdtc26gost341012256paramSetA, gost34112012256.New},
		{"512", "testdata/kz/user_gost2022_test.cer", filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt"), gost3410.CurveIdtc26gost341012512paramSetA, gost34112012512.New},
	} {
		issuer, certificate := readCertificate(t, profile.issuer), readCertificate(t, profile.certificate)
		var key gostSubjectPublicKeyInfo
		if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &key); err != nil {
			t.Fatal(err)
		}
		var point []byte
		if _, err := asn1.Unmarshal(key.PublicKey.Bytes, &point); err != nil {
			t.Fatal(err)
		}
		public, err := gost3410.NewPublicKeyLE(profile.newCurve(), point)
		if err != nil {
			t.Fatal(err)
		}
		h := profile.newHash()
		h.Write(certificate.RawTBSCertificate)
		digest := h.Sum(nil)
		invalidSignature := flipLastBit(certificate.Signature)
		fixtures = append(fixtures, fixture{
			name: profile.name, issuer: issuer, certificate: certificate,
			invalidCertificate: withCertificateFields(certificate, certificate.RawTBSCertificate, invalidSignature),
			algorithm:          outerSignatureAlgorithm(t, certificate.Raw), public: public,
			digest: digest, signature: certificate.Signature, invalidSignature: invalidSignature,
			issuerBefore: bytes.Clone(issuer.Raw), certificateBefore: bytes.Clone(certificate.Raw),
			pointBefore: public.RawLE(), digestBefore: bytes.Clone(digest), expectedCurve: profile.newCurve(),
		})
	}
	const workers, iterations = 8, 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Go(func() {
			<-start
			for iteration := range iterations {
				f := &fixtures[(worker+iteration)%len(fixtures)]
				if err := certsig.CheckCertificateSignature(f.certificate, f.issuer); err != nil {
					t.Errorf("worker %d, profile %s certificate: %v", worker, f.name, err)
					return
				}
				if err := certsig.CheckSignature(f.issuer, f.algorithm, f.certificate.RawTBSCertificate, f.signature); err != nil {
					t.Errorf("worker %d, profile %s signature: %v", worker, f.name, err)
					return
				}
				if err := certsig.CheckCertificateSignature(f.invalidCertificate, f.issuer); err == nil || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
					t.Errorf("worker %d, profile %s invalid certificate: %v", worker, f.name, err)
					return
				}
				if err := certsig.CheckSignature(f.issuer, f.algorithm, f.certificate.RawTBSCertificate, f.invalidSignature); err == nil || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
					t.Errorf("worker %d, profile %s invalid signature: %v", worker, f.name, err)
					return
				}
				verifier := gost3410.PublicKeyReverseDigestAndSignature{Pub: f.public}
				if valid, err := verifier.VerifyDigest(f.digest, f.signature); err != nil || !valid {
					t.Errorf("worker %d, profile %s shared public key: %t, %v", worker, f.name, valid, err)
					return
				}
				if valid, err := verifier.VerifyDigest(f.digest, f.invalidSignature); err != nil || valid {
					t.Errorf("worker %d, profile %s shared public key with invalid signature: %t, %v", worker, f.name, valid, err)
					return
				}
			}
		})
	}
	close(start)
	wg.Wait()
	for _, f := range fixtures {
		if !bytes.Equal(f.issuer.Raw, f.issuerBefore) || !bytes.Equal(f.certificate.Raw, f.certificateBefore) ||
			!bytes.Equal(f.public.RawLE(), f.pointBefore) || !bytes.Equal(f.digest, f.digestBefore) || !f.public.C.Equal(f.expectedCurve) {
			t.Errorf("profile %s concurrent verification mutated a shared input", f.name)
		}
	}
}

func TestCheckSignatureRejectsUnexpectedGostASN1(t *testing.T) {
	for _, profile := range []struct{ name, certificate, issuer string }{
		{"256", gost256Fixtures + "gost256-leaf.der", gost256Fixtures + "gost256-ca.der"},
		{"512", "testdata/kz/user_gost2022_test.cer", filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")},
	} {
		t.Run(profile.name, func(t *testing.T) {
			certificate, issuer := readCertificate(t, profile.certificate), readCertificate(t, profile.issuer)
			algorithm := outerSignatureAlgorithm(t, certificate.Raw)
			if err := certsig.CheckSignature(issuer, algorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				name       string
				parameters asn1.RawValue
				valid      bool
			}{
				{"absent", asn1.RawValue{}, true},
				{"NULL value", asn1.NullRawValue, true},
				{"NULL DER", asn1.RawValue{FullBytes: asn1.NullBytes}, true},
				{"integer", asn1.RawValue{FullBytes: marshalFixture(t, 1)}, false},
				{"OID", asn1.RawValue{FullBytes: marshalFixture(t, asn1.ObjectIdentifier{1, 2, 3})}, false},
				{"sequence", asn1.RawValue{FullBytes: []byte{0x30, 0}}, false},
				{"nonempty NULL", asn1.RawValue{FullBytes: []byte{5, 1, 0}}, false},
				{"truncated NULL", asn1.RawValue{FullBytes: []byte{5}}, false},
				{"trailing NULL", asn1.RawValue{FullBytes: []byte{5, 0, 5, 0}}, false},
			} {
				t.Run("signature parameters/"+test.name, func(t *testing.T) {
					changed := algorithm
					changed.Parameters = test.parameters
					err := certsig.CheckSignature(issuer, changed, certificate.RawTBSCertificate, certificate.Signature)
					if (err == nil) != test.valid {
						t.Fatalf("CheckSignature() = %v, want valid=%t", err, test.valid)
					}
				})
			}
			for _, test := range []string{"extra SPKI field", "duplicate public key", "malformed SPKI tail", "extra algorithm field", "duplicate key parameters", "malformed algorithm tail"} {
				t.Run(test, func(t *testing.T) {
					key := sequenceFixture(t, issuer.RawSubjectPublicKeyInfo)
					switch test {
					case "extra SPKI field":
						key = append(key, asn1.RawValue{FullBytes: asn1.NullBytes})
					case "duplicate public key":
						key = append(key, key[1])
					case "malformed SPKI tail":
						key = append(key, asn1.RawValue{FullBytes: []byte{0xff}})
					default:
						fields := sequenceFixture(t, key[0].FullBytes)
						extra := asn1.RawValue{FullBytes: asn1.NullBytes}
						switch test {
						case "duplicate key parameters":
							extra = fields[1]
						case "malformed algorithm tail":
							extra.FullBytes = []byte{0xff}
						}
						key[0] = asn1.RawValue{FullBytes: sequenceBytesFixture(t, append(fields, extra))}
					}
					// Exercise the actual x509 parsing path, not an inconsistent struct.
					outer := sequenceFixture(t, issuer.Raw)
					tbs := sequenceFixture(t, outer[0].FullBytes)
					if issuer.Version != 3 || len(tbs) < 7 {
						t.Fatal("fixture must be a v3 certificate")
					}
					tbs[6] = asn1.RawValue{FullBytes: sequenceBytesFixture(t, key)}
					outer[0] = asn1.RawValue{FullBytes: sequenceBytesFixture(t, tbs)}
					parsed, err := x509.ParseCertificate(sequenceBytesFixture(t, outer))
					if err != nil {
						return // A stricter standard-library parser may reject it first.
					}
					if err := certsig.CheckSignature(parsed, algorithm, certificate.RawTBSCertificate, certificate.Signature); err == nil {
						t.Fatal("accepted unexpected ASN.1 fields in a public key")
					}
				})
			}
		})
	}
}

func TestCheckCertificateSignatureRejectsUnexpectedGostASN1(t *testing.T) {
	for _, profile := range []struct{ name, certificate, issuer string }{
		{"256", gost256Fixtures + "gost256-delegate.der", gost256Fixtures + "gost256-ca.der"},
		{"512", "testdata/kz/user_gost2022_test.cer", filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")},
	} {
		t.Run(profile.name, func(t *testing.T) {
			certificate, issuer := readCertificate(t, profile.certificate), readCertificate(t, profile.issuer)
			if err := certsig.CheckCertificateSignature(certificate, issuer); err != nil {
				t.Fatal(err)
			}
			for _, test := range []string{"extra certificate field", "duplicate signature", "malformed certificate tail", "extra algorithm field", "unaligned signature"} {
				t.Run(test, func(t *testing.T) {
					fields := sequenceFixture(t, certificate.Raw)
					switch test {
					case "extra certificate field":
						fields = append(fields, asn1.RawValue{FullBytes: asn1.NullBytes})
					case "duplicate signature":
						fields = append(fields, fields[2])
					case "malformed certificate tail":
						fields = append(fields, asn1.RawValue{FullBytes: []byte{0xff}})
					case "extra algorithm field":
						algorithm := sequenceFixture(t, fields[1].FullBytes)
						fields[1] = asn1.RawValue{FullBytes: sequenceBytesFixture(t, append(algorithm, asn1.RawValue{FullBytes: asn1.NullBytes}))}
					case "unaligned signature":
						// RightAlign would restore the original signature when its high bit is zero.
						if certificate.Signature[0]&0x80 != 0 {
							t.Fatal("fixture must have a leading zero signature bit")
						}
						bits := bytes.Clone(fields[2].Bytes)
						bits[0] = 1
						for i := 1; i < len(bits)-1; i++ {
							bits[i] = bits[i]<<1 | bits[i+1]>>7
						}
						bits[len(bits)-1] <<= 1
						fields[2] = asn1.RawValue{FullBytes: marshalFixture(t, asn1.RawValue{Tag: asn1.TagBitString, Bytes: bits})}
					}
					parsed, err := x509.ParseCertificate(sequenceBytesFixture(t, fields))
					if err != nil {
						return
					}
					if err := certsig.CheckCertificateSignature(parsed, issuer); err == nil {
						t.Fatal("accepted malformed certificate ASN.1")
					}
				})
			}
		})
	}
}

func sequenceFixture(t testing.TB, encoded []byte) []asn1.RawValue {
	t.Helper()
	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(encoded, &sequence); err != nil || len(rest) != 0 || sequence.Tag != asn1.TagSequence {
		t.Fatalf("invalid sequence fixture: %v", err)
	}
	var fields []asn1.RawValue
	for rest := sequence.Bytes; len(rest) != 0; {
		var field asn1.RawValue
		remaining, err := asn1.Unmarshal(rest, &field)
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, field)
		rest = remaining
	}
	return fields
}

func sequenceBytesFixture(t *testing.T, fields []asn1.RawValue) []byte {
	t.Helper()
	var contents []byte
	for _, field := range fields {
		contents = append(contents, field.FullBytes...)
	}
	return marshalFixture(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: contents})
}

func TestCheckCertificateSignatureRejectsInconsistentGostFields(t *testing.T) {
	for _, profile := range []struct{ name, certificate, issuer string }{
		{"256", gost256Fixtures + "gost256-leaf.der", gost256Fixtures + "gost256-ca.der"},
		{"512", "testdata/kz/user_gost2022_test.cer", filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")},
	} {
		t.Run(profile.name, func(t *testing.T) {
			certificate, issuer := readCertificate(t, profile.certificate), readCertificate(t, profile.issuer)
			for _, test := range []string{"raw TBS", "raw signature", "outer algorithm parameters"} {
				t.Run(test, func(t *testing.T) {
					fields := sequenceFixture(t, certificate.Raw)
					switch test {
					case "raw TBS":
						fields[0].FullBytes = flipLastBit(fields[0].FullBytes)
					case "raw signature":
						fields[2].FullBytes = flipLastBit(fields[2].FullBytes)
					case "outer algorithm parameters":
						algorithm := outerSignatureAlgorithm(t, certificate.Raw)
						algorithm.Parameters = asn1.RawValue{}
						fields[1].FullBytes = marshalFixture(t, algorithm)
					}
					changed := *certificate
					changed.Raw = sequenceBytesFixture(t, fields)
					if err := certsig.CheckCertificateSignature(&changed, issuer); err == nil {
						t.Fatal("accepted inconsistent certificate Raw/parsed fields")
					}
				})
			}
		})
	}
}

func TestSignatureChecksRejectMissingCertificates(t *testing.T) {
	certificate := readCertificate(t, gost256Fixtures+"gost256-leaf.der")
	issuer := readCertificate(t, gost256Fixtures+"gost256-ca.der")
	for _, test := range []struct {
		name  string
		check func() error
	}{
		{"missing certificate", func() error { return certsig.CheckCertificateSignature(nil, issuer) }},
		{"missing issuer", func() error { return certsig.CheckCertificateSignature(certificate, nil) }},
		{"both missing", func() error { return certsig.CheckCertificateSignature(nil, nil) }},
		{"missing 256 signer", func() error {
			return certsig.CheckSignature(nil, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 1}}, nil, nil)
		}},
		{"missing 512 signer", func() error {
			return certsig.CheckSignature(nil, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 2}}, nil, nil)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.check(); err == nil {
				t.Fatal("missing certificate accepted")
			}
		})
	}
}

func TestCheckSignatureGostBoundsAndEncodings(t *testing.T) {
	for _, profile := range []struct {
		name, certificate, issuer string
		newCurve                  func() *gost3410.Curve
	}{
		{"256", gost256Fixtures + "gost256-leaf.der", gost256Fixtures + "gost256-ca.der", gost3410.CurveIdtc26gost341012256paramSetA},
		{"512", "testdata/kz/user_gost2022_test.cer", filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt"), gost3410.CurveIdtc26gost341012512paramSetA},
	} {
		t.Run(profile.name, func(t *testing.T) {
			certificate, issuer := readCertificate(t, profile.certificate), readCertificate(t, profile.issuer)
			algorithm := outerSignatureAlgorithm(t, certificate.Raw)
			curve := profile.newCurve()
			width := curve.PointSize()
			if err := certsig.CheckSignature(issuer, algorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
				t.Fatal(err)
			}
			for n := range len(issuer.RawSubjectPublicKeyInfo) {
				changed := *issuer
				changed.RawSubjectPublicKeyInfo = issuer.RawSubjectPublicKeyInfo[:n]
				if err := certsig.CheckSignature(&changed, algorithm, certificate.RawTBSCertificate, certificate.Signature); err == nil {
					t.Fatalf("accepted SPKI truncated to %d bytes", n)
				}
			}
			for _, n := range []int{0, 1, 2*width - 1, 2*width + 1, 4 * width} {
				if err := certsig.CheckSignature(issuer, algorithm, certificate.RawTBSCertificate, make([]byte, n)); err == nil {
					t.Fatalf("accepted %d-byte signature", n)
				}
			}
			maxScalar := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(width*8)), big.NewInt(1))
			for _, part := range []struct {
				name   string
				offset int
			}{{"r", 0}, {"s", width}} {
				for _, boundary := range []struct {
					name  string
					value *big.Int
				}{
					{"zero", big.NewInt(0)},
					{"one", big.NewInt(1)},
					{"q-1", new(big.Int).Sub(curve.Q, big.NewInt(1))},
					{"q", curve.Q},
					{"q+1", new(big.Int).Add(curve.Q, big.NewInt(1))},
					{"max", maxScalar},
				} {
					t.Run(part.name+"/"+boundary.name, func(t *testing.T) {
						signature := bytes.Clone(certificate.Signature)
						le := signature[part.offset : part.offset+width]
						boundary.value.FillBytes(le)
						slices.Reverse(le)
						if bytes.Equal(signature, certificate.Signature) {
							t.Fatal("boundary fixture must change the signature")
						}
						if err := certsig.CheckSignature(issuer, algorithm, certificate.RawTBSCertificate, signature); err == nil {
							t.Fatal("accepted changed signature scalar")
						}
					})
				}
			}
			var key gostSubjectPublicKeyInfo
			if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &key); err != nil {
				t.Fatal(err)
			}
			var point []byte
			if _, err := asn1.Unmarshal(key.PublicKey.Bytes, &point); err != nil {
				t.Fatal(err)
			}
			for _, offset := range []int{0, width} {
				for _, value := range []*big.Int{big.NewInt(0), new(big.Int).Sub(curve.P, big.NewInt(1)), curve.P, new(big.Int).Add(curve.P, big.NewInt(1)), maxScalar} {
					encodedPoint := bytes.Clone(point)
					value.FillBytes(encodedPoint[offset : offset+width])
					slices.Reverse(encodedPoint[offset : offset+width])
					encoded := marshalFixture(t, encodedPoint)
					changedKey := key
					changedKey.PublicKey = asn1.BitString{Bytes: encoded, BitLength: 8 * len(encoded)}
					changed := *issuer
					changed.RawSubjectPublicKeyInfo = marshalFixture(t, changedKey)
					if err := certsig.CheckSignature(&changed, algorithm, certificate.RawTBSCertificate, certificate.Signature); err == nil {
						t.Fatalf("accepted changed coordinate at offset %d = %x", offset, value)
					}
				}
			}
			for _, test := range []string{"reversed signature", "swapped signature scalars", "big-endian signature scalars", "big-endian key", "wrong point type", "trailing point data"} {
				t.Run(test, func(t *testing.T) {
					signature := bytes.Clone(certificate.Signature)
					changed := *issuer
					switch test {
					case "reversed signature":
						slices.Reverse(signature)
					case "swapped signature scalars":
						copy(signature[:width], certificate.Signature[width:])
						copy(signature[width:], certificate.Signature[:width])
					case "big-endian signature scalars":
						slices.Reverse(signature[:width])
						slices.Reverse(signature[width:])
					default:
						encodedPoint := bytes.Clone(point)
						if test == "big-endian key" {
							slices.Reverse(encodedPoint[:width])
							slices.Reverse(encodedPoint[width:])
						}
						encoded := marshalFixture(t, encodedPoint)
						switch test {
						case "wrong point type":
							encoded = asn1.NullBytes
						case "trailing point data":
							encoded = append(encoded, asn1.NullBytes...)
						}
						changedKey := key
						changedKey.PublicKey = asn1.BitString{Bytes: encoded, BitLength: 8 * len(encoded)}
						changed.RawSubjectPublicKeyInfo = marshalFixture(t, changedKey)
					}
					if err := certsig.CheckSignature(&changed, algorithm, certificate.RawTBSCertificate, signature); err == nil {
						t.Fatal("accepted wrong byte order or point encoding")
					}
				})
			}
		})
	}
}

func FuzzCheckGostSignature(f *testing.F) {
	certificates := []*x509.Certificate{
		readCertificate(f, gost256Fixtures+"gost256-leaf.der"),
		readCertificate(f, "testdata/kz/user_gost2022_test.cer"),
	}
	issuers := []*x509.Certificate{
		readCertificate(f, gost256Fixtures+"gost256-ca.der"),
		readCertificate(f, filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")),
	}
	algorithms := make([]pkix.AlgorithmIdentifier, len(certificates))
	for i, certificate := range certificates {
		algorithms[i] = outerSignatureAlgorithm(f, certificate.Raw)
		f.Add(uint8(i), uint8(0), issuers[i].RawSubjectPublicKeyInfo)
		f.Add(uint8(i), uint8(0), []byte{0x30, 0})
		f.Add(uint8(i), uint8(0), issuers[i].RawSubjectPublicKeyInfo[:len(issuers[i].RawSubjectPublicKeyInfo)-1])
		f.Add(uint8(i), uint8(1), certificate.Signature)
		f.Add(uint8(i), uint8(1), make([]byte, len(certificate.Signature)))
		f.Add(uint8(i), uint8(2), asn1.NullBytes)
		f.Add(uint8(i), uint8(2), []byte{5, 1, 0})
	}
	f.Fuzz(func(t *testing.T, profile, target uint8, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		i := int(profile) % len(certificates)
		issuer, algorithm := *issuers[i], algorithms[i]
		certificate := certificates[i]
		signature := certificate.Signature
		switch target % 3 {
		case 0:
			issuer.RawSubjectPublicKeyInfo = data
		case 1:
			signature = data
		case 2:
			algorithm.Parameters = asn1.RawValue{FullBytes: data}
		}
		before := bytes.Clone(data)
		// The parser and arithmetic must return errors for bad input.
		// They must not panic or change the caller's bytes.
		// Valid seeds reach verification on both curves.
		_ = certsig.CheckSignature(&issuer, algorithm, certificate.RawTBSCertificate, signature)
		if !bytes.Equal(data, before) {
			t.Fatal("signature verification mutated its input")
		}
	})
}

func FuzzCheckGostCertificate(f *testing.F) {
	certificates := []*x509.Certificate{
		readCertificate(f, gost256Fixtures+"gost256-leaf.der"),
		readCertificate(f, "testdata/kz/user_gost2022_test.cer"),
	}
	issuers := []*x509.Certificate{
		readCertificate(f, gost256Fixtures+"gost256-ca.der"),
		readCertificate(f, filepath.Join(kalkan, "test", "nca", "nca_gost2022_test.crt")),
	}
	for i, certificate := range certificates {
		f.Add(uint8(i), certificate.Raw)
		f.Add(uint8(i), certificate.Raw[:len(certificate.Raw)-1])
		f.Add(uint8(i), []byte{0x30, 0})
	}
	f.Fuzz(func(t *testing.T, profile uint8, data []byte) {
		if len(data) > 16*1024 {
			t.Skip()
		}
		i := int(profile) % len(certificates)
		before := bytes.Clone(data)
		if certificate, err := x509.ParseCertificate(data); err == nil {
			_ = certsig.CheckCertificateSignature(certificate, issuers[i])
		}
		// Also exercise Raw independently of x509's parser, as accepted by the API.
		certificate := *certificates[i]
		certificate.Raw = data
		_ = certsig.CheckCertificateSignature(&certificate, issuers[i])
		if !bytes.Equal(data, before) {
			t.Fatal("certificate verification mutated its input")
		}
	})
}
