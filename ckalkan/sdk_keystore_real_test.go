package ckalkan_test

import (
	"bytes"
	"path/filepath"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestRealKalkanCryptSDKAllPKCS12Stores(t *testing.T) {
	assets := sdkAssetsForIntegration(t)
	client := newRealClient(t, realSDKBufferOptions()...)
	data := []byte("ckalkan SDK GOST detached CMS roundtrip")

	for _, storePath := range assets.P12 {
		t.Run(filepath.Base(storePath), func(t *testing.T) {
			if err := client.LoadKeyStore(ckalkan.StorePKCS12, sdkTestPassword, storePath, ""); err != nil {
				t.Fatalf("LoadKeyStore(%s) failed: %v", storePath, err)
			}

			cert, err := client.X509ExportCertificateFromStore("", ckalkan.CertPEM)
			if err != nil {
				t.Fatalf("X509ExportCertificateFromStore(%s) failed: %v", storePath, err)
			}
			requireContains(t, "exported SDK certificate", cert, "-----BEGIN CERTIFICATE-----")

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
