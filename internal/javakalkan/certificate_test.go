package javakalkan

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestCertificateSignatureAlgorithmNativeNames(t *testing.T) {
	// Literal expectations were checked against OBJ_nid2ln in SDK 2.0.13.
	for _, tt := range []struct{ oid, name string }{
		{"1.2.840.113549.1.1.2", "md2WithRSAEncryption"},
		{"1.2.840.113549.1.1.4", "md5WithRSAEncryption"},
		{"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"},
		{"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
		{"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
		{"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
		{"1.2.840.10040.4.3", "dsaWithSHA1"},
		{"2.16.840.1.101.3.4.3.2", "dsa_with_SHA256"},
		{"1.2.840.10045.4.1", "ecdsa-with-SHA1"},
		{"1.2.840.10045.4.3.2", "ecdsa-with-SHA256"},
		{"1.2.840.10045.4.3.3", "ecdsa-with-SHA384"},
		{"1.2.840.10045.4.3.4", "ecdsa-with-SHA512"},
		{"1.3.101.112", "ED25519"},
		{"1.2.398.3.10.1.1.1.1", "GOST 34.310-2004"},
		{"1.2.398.3.10.1.1.1.2", "GOST 34.311-95 with GOST 34.310-2004"},
		{"1.2.398.3.10.1.1.2.1", "GOST R 34.10-2015 with 256 bit modulus"},
		{"1.2.398.3.10.1.1.2.2", "GOST R 34.10-2015 with 512 bit modulus"},
		{"1.2.398.3.10.1.1.2.3.1", "GOST R 34.10-2015 with GOST R 34.11-2015 (256 bit)"},
		{"1.2.398.3.10.1.1.2.3.2", "GOST R 34.10-2015 with GOST R 34.11-2015 (512 bit)"},
		{"1.3.6.1.4.1.6801.1.2.2", "GOST Old 34.311-95 with GOST Old 34.310-2004"},
		{"1.2.643.2.2.3", "GOST R 34.11-94 with GOST R 34.10-2001"},
		{"1.2.643.2.2.4", "GOST R 34.11-94 with GOST R 34.10-94"},
		{"1.2.643.7.1.1.3.2", "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)"},
		{"1.2.643.7.1.1.3.3", "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)"},
		{"1.2.398.3.3.99", ""},
	} {
		t.Run(tt.oid, func(t *testing.T) {
			parts := strings.Split(tt.oid, ".")
			oid := make(asn1.ObjectIdentifier, 0, len(parts))
			for _, part := range parts {
				n, err := strconv.Atoi(part)
				if err != nil {
					t.Fatal(err)
				}
				oid = append(oid, n)
			}
			der, err := asn1.Marshal(struct {
				TBS       asn1.RawValue
				Algorithm pkix.AlgorithmIdentifier
				Signature asn1.BitString
			}{asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true}, pkix.AlgorithmIdentifier{Algorithm: oid}, asn1.BitString{}})
			if err != nil {
				t.Fatal(err)
			}
			// Metadata must use the encoded algorithm, including when Go's parsed
			// enum is unknown or does not preserve the original algorithm OID.
			got, err := certificateProperty(&x509.Certificate{Raw: der, SignatureAlgorithm: x509.SHA256WithRSA}, ckalkan.CertPropSignatureAlg)
			want := tt.oid
			if tt.name != "" {
				want = "signatureAlgorithm=" + tt.name + "(" + tt.oid + ")"
			}
			if err != nil || got != want {
				t.Fatalf("signature property = %q, %v; want %q", got, err, want)
			}
		})
	}
}

func TestCertificateSignatureAlgorithmRSAPSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []x509.SignatureAlgorithm{x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS} {
		t.Run(algorithm.String(), func(t *testing.T) {
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PSS metadata"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), SignatureAlgorithm: algorithm,
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			got, err := certificateProperty(cert, ckalkan.CertPropSignatureAlg)
			if err != nil || got != "signatureAlgorithm=rsassaPss(1.2.840.113549.1.1.10)" {
				t.Fatalf("PSS signature property = %q, %v", got, err)
			}
		})
	}
}

func TestCertificateSignatureAlgorithmGOSTFixture(t *testing.T) {
	encoded, err := os.ReadFile("../../testdata/examples/test_CERT_GOST.txt")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(encoded, []byte("version https://git-lfs.github.com/spec/v1")) {
		t.Skip("GOST fixture is a Git LFS pointer")
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("missing GOST fixture certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := certificateProperty(cert, ckalkan.CertPropSignatureAlg)
	if err != nil || got != "signatureAlgorithm=GOST 34.311-95 with GOST 34.310-2004(1.2.398.3.10.1.1.1.2)" {
		t.Fatalf("GOST fixture signature property = %q, %v", got, err)
	}
	if _, err := certificateProperty(&x509.Certificate{Raw: []byte("not DER")}, ckalkan.CertPropSignatureAlg); err == nil {
		t.Fatal("malformed certificate algorithm accepted")
	}
}
