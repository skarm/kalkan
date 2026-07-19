//go:build linux && cgo

package kalkancrypt_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestZipConVerifyFixtures(t *testing.T) {
	ctx := openContext(t)
	assets := loadFixtureAssets(t)
	loadCertificates(t, ctx, assets)

	for _, zipPath := range zipFixtures(t, assets) {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			result, err := ctx.ZipConVerify(copyZIPFixture(t, zipPath), noCheckCertTime, 1<<20)
			requireBufferOK(t, "ZipConVerify", result, err)
			if !bytes.Contains(result.Data, []byte("Verify - OK")) {
				t.Fatalf("ZipConVerify info = %q, want Verify - OK", result.Data)
			}
		})
	}
}

func TestGetCertFromZipFileFixtures(t *testing.T) {
	ctx := openContext(t)
	assets := loadFixtureAssets(t)
	loadCertificates(t, ctx, assets)

	for _, zipPath := range zipFixtures(t, assets) {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			cert, err := ctx.GetCertFromZipFile(kalkancrypt.GetCertFromZipFileCall{
				ZipFile:  copyZIPFixture(t, zipPath),
				Flags:    noCheckCertTime,
				Capacity: 1 << 20,
			})
			if err != nil {
				t.Fatalf("GetCertFromZipFile returned Go error: %v", err)
			}
			if cert.Code != kcrOK {
				t.Fatalf("GetCertFromZipFile code = %#x, want %#x", cert.Code, kcrOK)
			}
			if cert.OutLen != len(cert.Data) {
				t.Fatalf("GetCertFromZipFile OutLen = %d, data length = %d", cert.OutLen, len(cert.Data))
			}
		})
	}
}

func TestZipConSignCreatesContainer(t *testing.T) {
	ctx := openContext(t)
	loadPKCS12Fixture(t, ctx)

	outDir := t.TempDir()
	inputPath := filepath.Join(outDir, "payload.txt")
	if err := os.WriteFile(inputPath, []byte("kalkancrypt low-level ZIP payload"), 0o644); err != nil {
		t.Fatalf("write ZIP payload: %v", err)
	}

	if code := ctx.ZipConSign(kalkancrypt.ZipConSignCall{
		FilePath: inputPath,
		Name:     "signed-by-kalkancrypt-test",
		OutDir:   outDir,
		Flags:    noCheckCertTime,
	}); code != kcrOK {
		t.Fatalf("ZipConSign = %#x, want %#x", code, kcrOK)
	}

	if _, ok := firstExistingFile(
		filepath.Join(outDir, "signed-by-kalkancrypt-test"),
		filepath.Join(outDir, "signed-by-kalkancrypt-test.zip"),
	); !ok {
		t.Fatalf("ZipConSign did not create output in %s", outDir)
	}
}
