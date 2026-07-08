package ckalkan_test

import (
	"os"
	"path/filepath"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestZIPFixtures(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	loadCertificates(t, client, assets)

	for _, zipPath := range assets.ZIPs {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			isolatedPath := copyZIPFixture(t, zipPath)
			info, err := client.ZipConVerify(isolatedPath, ckalkan.NoCheckCertTime)
			if err != nil {
				t.Fatalf("ZipConVerify(%s) failed: %v", zipPath, err)
			}
			requireStringContains(t, "ZIP verify info", info, "Checking zip - OK")
			requireStringContains(t, "ZIP verify info", info, "Verify - OK")

			cert, err := client.GetCertFromZipFile(isolatedPath, ckalkan.NoCheckCertTime, 0)
			if err != nil {
				t.Fatalf("GetCertFromZipFile(%s) failed: %v", zipPath, err)
			}
			if len(cert) == 0 {
				t.Logf("GetCertFromZipFile(%s) returned KCR_OK with an empty certificate; root API rejects this output", filepath.Base(zipPath))
			}
		})
	}
}

func TestZipSignAndExpectedErrors(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixturePassword, chooseStore(t, assets.P12), ""); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}

	badDigest := []byte{1, 2, 3}
	if _, err := client.SignHash("", ckalkan.SignCMS|ckalkan.OutBase64|ckalkan.NoCheckCertTime, badDigest); err == nil {
		t.Fatal("SignHash unexpectedly accepted an invalid digest length")
	} else {
		kalkanErr := requireKalkanError(t, "SignHash(short digest)", err)
		if kalkanErr.Code != ckalkan.ErrorInvalidDigestLen {
			t.Fatalf("SignHash(short digest) code = %v, want ErrorInvalidDigestLen", kalkanErr.Code)
		}
	}

	outDir := t.TempDir()
	inputPath := filepath.Join(outDir, "payload.txt")
	if err := os.WriteFile(inputPath, []byte("ckalkan ZIP fixture payload"), 0o644); err != nil {
		t.Fatalf("write ZIP payload: %v", err)
	}
	if err := client.ZipConSign(ckalkan.ZipConSignRequest{FilePath: inputPath, Name: "signed-by-fixture-key", OutDir: outDir, Flags: ckalkan.NoCheckCertTime}); err != nil {
		t.Fatalf("ZipConSign failed: %v", err)
	}
	if _, ok := firstExistingFile(filepath.Join(outDir, "signed-by-fixture-key"), filepath.Join(outDir, "signed-by-fixture-key.zip")); !ok {
		t.Fatalf("ZipConSign did not create output in %s", outDir)
	}

	if _, err := client.GetTokens(ckalkan.StoreKazToken); err == nil {
		t.Log("GetTokens(StoreKazToken) found a token in this environment")
	} else {
		requireKalkanError(t, "GetTokens(StoreKazToken)", err)
	}
	if _, err := client.GetCertificatesList(); err == nil {
		t.Log("GetCertificatesList returned certificate aliases")
	} else {
		requireKalkanError(t, "GetCertificatesList", err)
	}

	if !skipMalformedUVerifyDataSmokeOnWindows(t) {
		if _, err := client.UVerifyData(ckalkan.VerifyDataRequest{Flags: ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.DetachedData | ckalkan.NoCheckCertTime, Data: []byte("not-a-file"), Signature: []byte("not-a-signature")}); err == nil {
			t.Fatal("UVerifyData unexpectedly accepted invalid input")
		} else {
			requireKalkanError(t, "UVerifyData(invalid)", err)
		}
	}
}
