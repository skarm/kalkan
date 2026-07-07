//go:build linux && cgo

package kalkancrypt_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestContextZipMethodsWithSDKZip(t *testing.T) {
	ctx := openContext(t)
	assets := sdkAssetsForIntegration(t)
	loadSDKCertificates(t, ctx, assets)

	var failures []string
	var zipPath string
	var verifyInfo []byte
	for _, candidate := range sdkZIPFixtures(t, assets) {
		verifyResult, err := ctx.ZipConVerify(candidate, noCheckCertTime, 1<<20)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: Go error: %v", filepath.Base(candidate), err))
			continue
		}
		if verifyResult.Code != kcrOK {
			failures = append(failures, fmt.Sprintf("%s: code=%#x", filepath.Base(candidate), verifyResult.Code))
			continue
		}
		if verifyResult.OutLen != len(verifyResult.Data) {
			failures = append(failures, fmt.Sprintf("%s: outLen=%d dataLen=%d", filepath.Base(candidate), verifyResult.OutLen, len(verifyResult.Data)))
			continue
		}
		if len(verifyResult.Data) == 0 {
			failures = append(failures, filepath.Base(candidate)+": empty verify info")
			continue
		}
		if !bytes.Contains(verifyResult.Data, []byte("Verify - OK")) {
			failures = append(failures, fmt.Sprintf("%s: verify info=%q", filepath.Base(candidate), verifyResult.Data))
			continue
		}

		zipPath = candidate
		verifyInfo = verifyResult.Data
		break
	}
	if zipPath == "" {
		t.Fatalf("no SDK ZIP fixture could be verified:\n%s", strings.Join(failures, "\n"))
	}
	t.Logf("verified SDK ZIP fixture %s: %q", filepath.Base(zipPath), verifyInfo)

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
