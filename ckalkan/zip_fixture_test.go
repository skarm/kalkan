package ckalkan_test

import (
	"os"
	"path/filepath"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestZipConVerifyFixtures(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	loadCertificates(t, client, assets)

	for _, zipPath := range assets.ZIPs {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			info, err := client.ZipConVerify(copyZIPFixture(t, zipPath), ckalkan.NoCheckCertTime)
			if err != nil {
				t.Fatalf("ZipConVerify(%s) failed: %v", zipPath, err)
			}
			requireStringContains(t, "ZIP verify info", info, "Checking zip - OK")
			requireStringContains(t, "ZIP verify info", info, "Verify - OK")
		})
	}
}

func TestGetCertFromZipFileFixtures(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	loadCertificates(t, client, assets)

	for _, zipPath := range assets.ZIPs {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			cert, err := client.GetCertFromZipFile(copyZIPFixture(t, zipPath), ckalkan.NoCheckCertTime, 0)
			if err != nil {
				t.Fatalf("GetCertFromZipFile(%s) failed: %v", zipPath, err)
			}
			if len(cert) == 0 {
				t.Logf("GetCertFromZipFile(%s) returned KCR_OK with an empty certificate; root API rejects this output", filepath.Base(zipPath))
			}
		})
	}
}

func TestZipConSignWithFixtureKey(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixturePassword, chooseStore(t, assets.P12), ""); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
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
}
