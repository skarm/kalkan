//go:build linux && cgo

package kalkancrypt_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestContextZipMethodsWithSDKZip(t *testing.T) {
	ctx := openContext(t)
	assets := sdkAssetsForIntegration(t)
	loadSDKCertificates(t, ctx, assets)

	zipPath := firstSDKZip(t, assets)
	verifyResult, err := ctx.ZipConVerify(zipPath, noCheckCertTime, 1<<20)
	verifyInfo := requireBufferOK(t, "ZipConVerify", verifyResult, err)
	if !bytes.Contains(verifyInfo, []byte("Verify - OK")) {
		t.Fatalf("ZipConVerify info = %q, want Verify - OK", verifyInfo)
	}

	certResult, err := ctx.GetCertFromZipFile(zipPath, noCheckCertTime, 0, 1<<20)
	if err != nil {
		t.Fatalf("GetCertFromZipFile returned Go error: %v", err)
	}
	if certResult.Code != kcrOK {
		t.Fatalf("GetCertFromZipFile code = %#x, want %#x", certResult.Code, kcrOK)
	}
	if certResult.OutLen != len(certResult.Data) {
		t.Fatalf("GetCertFromZipFile OutLen = %d, data length = %d", certResult.OutLen, len(certResult.Data))
	}
}

func TestContextZipConSignCreatesContainer(t *testing.T) {
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
