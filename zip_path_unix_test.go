//go:build darwin || linux

package kalkan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestVerifyZIPPassesFIFOInputToNative(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "source.zip")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	assertVerifyZIPReceivesPath(t, fifoPath)
}

func TestVerifyZIPPassesSymlinkSourceToNative(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.zip")
	if err := os.WriteFile(targetPath, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "source.zip")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	assertVerifyZIPReceivesPath(t, linkPath)
}

func TestExtractZIPSignerCertificatePassesFIFOToNative(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "source.zip")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	assertExtractZIPSignerCertificateReceivesPath(t, fifoPath)
}

func TestExtractZIPSignerCertificatePassesSymlinkToNative(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.zip")
	if err := os.WriteFile(targetPath, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "source.zip")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	assertExtractZIPSignerCertificateReceivesPath(t, linkPath)
}

func TestSignZIPPassesFIFOInputToNative(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "source.zip")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	assertSignZIPReceivesInputPath(t, fifoPath, filepath.Join(dir, "signed.zip"))
}

func TestSignZIPPassesSymlinkInputToNative(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.zip")
	if err := os.WriteFile(targetPath, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "source.zip")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	assertSignZIPReceivesInputPath(t, linkPath, filepath.Join(dir, "signed.zip"))
}

func assertVerifyZIPReceivesPath(t *testing.T, path string) {
	t.Helper()

	var calls int
	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			calls++
			if zipFile != path {
				t.Fatalf("zip path = %q, want %q", zipFile, path)
			}
			return "Checking zip - OK", nil
		},
		getCertFromZipFileFunc: func(string, ckalkan.Flag, int) ([]byte, error) {
			t.Fatal("VerifyZIP called native GetCertFromZipFile")
			return nil, nil
		},
	}
	client := &Client{library: native}

	if _, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{Path: path}); err != nil {
		t.Fatalf("VerifyZIP returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("native ZipConVerify calls = %d, want 1", calls)
	}
}

func assertExtractZIPSignerCertificateReceivesPath(t *testing.T, path string) {
	t.Helper()

	var called bool
	native := &fakeNative{
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			called = true
			if zipFile != path {
				t.Fatalf("zip path = %q, want %q", zipFile, path)
			}
			return []byte("zip-cert"), nil
		},
	}
	client := &Client{library: native}

	if _, err := client.ExtractZIPSignerCertificate(context.Background(), ExtractZIPSignerCertificateRequest{Path: path}); err != nil {
		t.Fatalf("ExtractZIPSignerCertificate returned error: %v", err)
	}
	if !called {
		t.Fatal("ExtractZIPSignerCertificate did not call native")
	}
}

func assertSignZIPReceivesInputPath(t *testing.T, inputPath, outputPath string) {
	t.Helper()

	var called bool
	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			called = true
			if req.FilePath != inputPath {
				t.Fatalf("input path = %q, want %q", req.FilePath, inputPath)
			}
			return os.WriteFile(outputPath, []byte("zip"), 0o600)
		},
	}
	client := &Client{library: native}

	if _, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  inputPath,
		OutputPath: outputPath,
	}); err != nil {
		t.Fatalf("SignZIP returned error: %v", err)
	}
	if !called {
		t.Fatal("SignZIP did not call native")
	}
}

func TestSignZIPRejectsExistingDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "signed.zip")
	if err := os.Symlink(filepath.Join(dir, "missing-target.zip"), outputPath); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			t.Fatal("SignZIP called native ZipConSign for a pre-existing dangling symlink output")
			return nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  filepath.Join(dir, "payload.txt"),
		OutputPath: outputPath,
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("SignZIP error = %v, want existing output rejection", err)
	}
}
