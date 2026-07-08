package ckalkan_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestAllPKCS12Stores(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	data := []byte("ckalkan fixture GOST detached CMS roundtrip")
	serials := make(map[string]string)

	for _, storePath := range assets.P12 {
		t.Run(filepath.Base(storePath), func(t *testing.T) {
			if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixturePassword, storePath, ""); err != nil {
				t.Fatalf("LoadKeyStore(%s) failed: %v", storePath, err)
			}

			cert, err := client.X509ExportCertificateFromStore("", ckalkan.CertPEM)
			if err != nil {
				t.Fatalf("X509ExportCertificateFromStore(%s) failed: %v", storePath, err)
			}
			requireContains(t, "exported fixture certificate", cert, "-----BEGIN CERTIFICATE-----")
			parsedCert := parseStoreCertificate(t, cert)
			assertStoreCertificateSubject(t, storePath, parsedCert, serials)

			cn, err := client.X509CertificateGetInfo(cert, ckalkan.CertPropSubjectCommonName)
			if err != nil {
				t.Fatalf("X509CertificateGetInfo(CommonName) failed: %v", err)
			}
			if len(bytes.TrimSpace(cn)) == 0 {
				t.Fatal("X509CertificateGetInfo(CommonName) returned empty data")
			}

			sig, err := client.SignData("", ckalkan.SignCMS|ckalkan.OutBase64|ckalkan.DetachedData|ckalkan.NoCheckCertTime, data, nil)
			if err != nil {
				t.Fatalf("SignData(detached CMS) failed: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("SignData(detached CMS) returned empty data")
			}

			verified, err := client.VerifyData(ckalkan.VerifyDataRequest{
				Flags:              ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.DetachedData | ckalkan.NoCheckCertTime,
				Data:               data,
				Signature:          sig,
				VerifyInfoCapacity: 1 << 20,
				DataCapacity:       1 << 20,
				CertCapacity:       1 << 20,
			})
			if err != nil {
				t.Fatalf("VerifyData(detached CMS) failed: %v", err)
			}
			requireStringContains(t, "detached CMS verify info", verified.VerifyInfo, "Verify - OK")
		})
	}
}

func assertStoreCertificateSubject(t *testing.T, storePath string, cert *x509.Certificate, serials map[string]string) {
	t.Helper()

	serial := cert.SerialNumber.String()
	if serial == "" || serial == "0" {
		t.Fatalf("exported fixture certificate serial = %q", serial)
	}
	if previousStore := serials[serial]; previousStore != "" {
		t.Fatalf("exported fixture certificate serial %s is shared by %s and %s", serial, previousStore, storePath)
	}
	serials[serial] = storePath
	if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "KZ" {
		t.Fatalf("exported fixture certificate country = %#v, want KZ", cert.Subject.Country)
	}
	if cert.Subject.SerialNumber != "" && !strings.HasPrefix(cert.Subject.SerialNumber, "IIN") {
		t.Fatalf("exported fixture certificate subject serial = %q, want IIN prefix", cert.Subject.SerialNumber)
	}
	if len(cert.Subject.OrganizationalUnit) == 0 {
		return
	}
	for _, organizationalUnit := range cert.Subject.OrganizationalUnit {
		if strings.HasPrefix(organizationalUnit, "BIN") {
			return
		}
	}
	t.Fatalf("exported fixture certificate OU = %#v, want a BIN-prefixed value when OU is present", cert.Subject.OrganizationalUnit)
}

func TestPKCS12RejectsWrongPassword(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	storePath := chooseStore(t, assets.P12)

	err := client.LoadKeyStore(ckalkan.StorePKCS12, "not-"+fixturePassword, storePath, "")
	if err == nil {
		t.Fatalf("LoadKeyStore(%s) unexpectedly accepted the wrong password", storePath)
	}
	requireKalkanError(t, "LoadKeyStore(wrong password)", err)
}

func parseStoreCertificate(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("exported fixture certificate PEM block = %#v", block)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse exported fixture certificate: %v", err)
	}
	return cert
}
