package ckalkan_test

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
	"strconv"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestCertificateAndHashMethods(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	loadCertificates(t, client, assets)

	primaryStore := chooseStore(t, assets.P12)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixturePassword, primaryStore, ""); err != nil {
		t.Fatalf("LoadKeyStore(%s) failed: %v", primaryStore, err)
	}
	cert, err := client.X509ExportCertificateFromStore("", ckalkan.CertPEM)
	if err != nil {
		t.Fatalf("X509ExportCertificateFromStore failed: %v", err)
	}

	successProps := map[ckalkan.CertProp]string{
		ckalkan.CertPropIssuerCountryName:   "C=KZ",
		ckalkan.CertPropIssuerCommonName:    "CN=",
		ckalkan.CertPropSubjectCountryName:  "C=KZ",
		ckalkan.CertPropSubjectCommonName:   "CN=",
		ckalkan.CertPropSubjectGivenName:    "GN=",
		ckalkan.CertPropSubjectSurname:      "SN=",
		ckalkan.CertPropSubjectSerialNumber: "serialNumber=",
		ckalkan.CertPropNotBefore:           "notBefore=",
		ckalkan.CertPropNotAfter:            "notAfter=",
		ckalkan.CertPropKeyUsage:            "keyUsage=",
		ckalkan.CertPropExtKeyUsage:         "extendedKeyUsage=",
		ckalkan.CertPropAuthKeyID:           "authorityKeyIdentifier=",
		ckalkan.CertPropSubjKeyID:           "subjectKeyIdentifier=",
		ckalkan.CertPropCertSN:              "certificateSerialNumber=",
		ckalkan.CertPropIssuerDN:            "CN =",
		ckalkan.CertPropSubjectDN:           "CN =",
		ckalkan.CertPropSignatureAlg:        "GOST R 34.10-2015",
		ckalkan.CertPropPubKey:              "M",
		ckalkan.CertPropPoliciesID:          "certificatePolicies=",
	}
	optionalProps := map[ckalkan.CertProp]string{
		ckalkan.CertPropOCSP:        "OCSP=",
		ckalkan.CertPropGetCRL:      "crlDistributionPoints=",
		ckalkan.CertPropGetDeltaCRL: "freshestCRL=",
	}
	props := []ckalkan.CertProp{
		ckalkan.CertPropIssuerCountryName,
		ckalkan.CertPropIssuerSOPN,
		ckalkan.CertPropIssuerLocalityName,
		ckalkan.CertPropIssuerOrgName,
		ckalkan.CertPropIssuerOrgUnitName,
		ckalkan.CertPropIssuerCommonName,
		ckalkan.CertPropSubjectCountryName,
		ckalkan.CertPropSubjectSOPN,
		ckalkan.CertPropSubjectLocalityName,
		ckalkan.CertPropSubjectCommonName,
		ckalkan.CertPropSubjectGivenName,
		ckalkan.CertPropSubjectSurname,
		ckalkan.CertPropSubjectSerialNumber,
		ckalkan.CertPropSubjectEmail,
		ckalkan.CertPropSubjectOrgName,
		ckalkan.CertPropSubjectOrgUnitName,
		ckalkan.CertPropSubjectBC,
		ckalkan.CertPropSubjectDC,
		ckalkan.CertPropNotBefore,
		ckalkan.CertPropNotAfter,
		ckalkan.CertPropKeyUsage,
		ckalkan.CertPropExtKeyUsage,
		ckalkan.CertPropAuthKeyID,
		ckalkan.CertPropSubjKeyID,
		ckalkan.CertPropCertSN,
		ckalkan.CertPropIssuerDN,
		ckalkan.CertPropSubjectDN,
		ckalkan.CertPropSignatureAlg,
		ckalkan.CertPropPubKey,
		ckalkan.CertPropPoliciesID,
		ckalkan.CertPropOCSP,
		ckalkan.CertPropGetCRL,
		ckalkan.CertPropGetDeltaCRL,
	}
	for _, prop := range props {
		info, err := client.X509CertificateGetInfo(cert, prop)
		want, shouldSucceed := successProps[prop]
		if shouldSucceed {
			if err != nil {
				t.Fatalf("X509CertificateGetInfo(%v) failed: %v", prop, err)
			}
			requireContains(t, certPropLabel(prop), info, want)
			continue
		}
		if want, ok := optionalProps[prop]; ok {
			if err == nil {
				requireContains(t, certPropLabel(prop), info, want)
				continue
			}
			kalkanErr := requireKalkanError(t, certPropCall(prop), err)
			if kalkanErr.Code == ckalkan.ErrorGetCertProp {
				continue
			}
			t.Fatalf("X509CertificateGetInfo(%v) code = %v, want success or ErrorGetCertProp", prop, kalkanErr.Code)
		}
		if err == nil {
			t.Fatalf("X509CertificateGetInfo(%v) unexpectedly succeeded with %q", prop, info)
		}
		kalkanErr := requireKalkanError(t, certPropCall(prop), err)
		if kalkanErr.Code != ckalkan.ErrorGetCertProp {
			t.Fatalf("X509CertificateGetInfo(%v) code = %v, want ErrorGetCertProp", prop, kalkanErr.Code)
		}
	}

	data := []byte("ckalkan fixture hash data")
	sha, err := client.HashData(ckalkan.SHA256, 0, data)
	if err != nil {
		t.Fatalf("HashData(sha256) failed: %v", err)
	}
	wantSHA := sha256.Sum256(data)
	if !bytes.Equal(sha, wantSHA[:]) {
		t.Fatalf("HashData(sha256) = %x, want %x", sha, wantSHA)
	}
	gost, err := client.HashData(ckalkan.GOST95, 0, data)
	if err != nil {
		t.Fatalf("HashData(Gost34311_95) failed: %v", err)
	}
	if len(gost) != 32 {
		t.Fatalf("HashData(Gost34311_95) length = %d, want 32", len(gost))
	}

	_, err = client.X509ValidateCertificate(ckalkan.ValidateCertificateRequest{
		Certificate:    cert,
		ValidationType: ckalkan.UseNothing,
		ValidationPath: filepath.Join(assets.Root, "certs"),
		Flags:          ckalkan.NoCheckCertTime,
		OutputCapacity: 1 << 20,
		OCSPCapacity:   1 << 20,
	})
	// The fixture certificates bundled here are historical test certificates. Current
	// KalkanCrypt builds report an expected chain/date error, but this still covers
	// the ABI and native error path with a real GOST certificate.
	if err == nil {
		t.Log("X509ValidateCertificate accepted the fixture certificate")
	} else {
		_ = requireKalkanError(t, "X509ValidateCertificate", err)
	}
}

func certPropLabel(prop ckalkan.CertProp) string {
	return "cert prop " + strconv.Itoa(int(prop))
}

func certPropCall(prop ckalkan.CertProp) string {
	return "X509CertificateGetInfo(" + strconv.Itoa(int(prop)) + ")"
}
