package kalkan

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateAndCRLFixturesAreConsistent(t *testing.T) {
	root := readDERCertificateFixture(t, filepath.Join("testdata", "certs", "root_test_gost_2022.cer"))
	intermediate := readDERCertificateFixture(t, filepath.Join("testdata", "certs", "nca_gost2022_test.cer"))

	if !bytes.Equal(root.RawSubject, root.RawIssuer) {
		t.Fatal("root_test_gost_2022 is not self-issued")
	}
	if !bytes.Equal(intermediate.RawIssuer, root.RawSubject) {
		t.Fatal("nca_gost2022_test issuer does not match root_test_gost_2022 subject")
	}
	requireCertificateCountry(t, root, "KZ")
	requireCertificateCountry(t, intermediate, "KZ")
	if root.NotBefore != time.Date(2022, 7, 7, 9, 5, 52, 0, time.UTC) {
		t.Fatalf("root notBefore = %s", root.NotBefore)
	}
	if root.NotAfter != time.Date(2032, 7, 7, 9, 5, 52, 0, time.UTC) {
		t.Fatalf("root notAfter = %s", root.NotAfter)
	}
	if intermediate.NotBefore != time.Date(2022, 7, 7, 9, 55, 23, 0, time.UTC) {
		t.Fatalf("intermediate notBefore = %s", intermediate.NotBefore)
	}
	if intermediate.NotAfter != time.Date(2032, 7, 4, 9, 55, 23, 0, time.UTC) {
		t.Fatalf("intermediate notAfter = %s", intermediate.NotAfter)
	}

	for _, crlPath := range []string{
		filepath.Join("testdata", "certs", "nca_gost2022_test.crl"),
		filepath.Join("testdata", "certs", "nca_gost2022_d_test.crl"),
	} {
		crl := readDERCRLFixture(t, crlPath)
		if !bytes.Equal(crl.RawIssuer, intermediate.RawSubject) {
			t.Fatalf("%s issuer does not match intermediate subject", crlPath)
		}
		if !crl.NextUpdate.After(crl.ThisUpdate) {
			t.Fatalf("%s nextUpdate %s is not after thisUpdate %s", crlPath, crl.NextUpdate, crl.ThisUpdate)
		}
	}
}

func TestPEMCertificateFixtureParsesKazakhstanSubject(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "examples", "test_CERT_GOST.txt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("test_CERT_GOST.txt PEM block = %#v", block)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse test_CERT_GOST.txt: %v", err)
	}
	requireCertificateCountry(t, cert, "KZ")
	if cert.Subject.SerialNumber != "IIN123456789012" {
		t.Fatalf("subject serial number = %q", cert.Subject.SerialNumber)
	}
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "BIN123456789021" {
		t.Fatalf("subject organizational unit = %#v", cert.Subject.OrganizationalUnit)
	}
}

func readDERCertificateFixture(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cert
}

func readDERCRLFixture(t *testing.T, path string) *x509.RevocationList {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return crl
}

func requireCertificateCountry(t *testing.T, cert *x509.Certificate, country string) {
	t.Helper()

	if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != country {
		t.Fatalf("certificate %s country = %#v, want %s", cert.Subject.CommonName, cert.Subject.Country, country)
	}
}
