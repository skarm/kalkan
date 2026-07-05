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

	assertVerifyZIPWithSignerCertificateReceivesPath(t, fifoPath)
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

	assertVerifyZIPWithSignerCertificateReceivesPath(t, linkPath)
}

func TestVerifyZIPWithoutSignerCertificatePassesFIFOInputToNative(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "source.zip")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	assertVerifyZIPReceivesPath(t, fifoPath)
}

func TestVerifyZIPWithoutSignerCertificatePassesSymlinkToNative(t *testing.T) {
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

func TestZIPSignerCertificatePassesFIFOInputToNative(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "source.zip")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	assertZIPSignerCertificateReceivesPath(t, fifoPath)
}

func TestZIPSignerCertificatePassesSymlinkToNative(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.zip")
	if err := os.WriteFile(targetPath, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "source.zip")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	assertZIPSignerCertificateReceivesPath(t, linkPath)
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

func assertVerifyZIPWithSignerCertificateReceivesPath(t *testing.T, path string) {
	t.Helper()

	var verifyCalled bool
	var certCalled bool
	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			verifyCalled = true
			if zipFile != path {
				t.Fatalf("verify path = %q, want %q", zipFile, path)
			}
			return "Checking zip - OK", nil
		},
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			certCalled = true
			if zipFile != path {
				t.Fatalf("cert path = %q, want %q", zipFile, path)
			}
			return []byte("zip-cert"), nil
		},
	}
	client := &Client{library: native}

	if _, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{
		Path:                    path,
		ReturnSignerCertificate: true,
	}); err != nil {
		t.Fatalf("VerifyZIP returned error: %v", err)
	}
	if !verifyCalled || !certCalled {
		t.Fatalf("native calls: verify=%v cert=%v, want both", verifyCalled, certCalled)
	}
}

func assertVerifyZIPReceivesPath(t *testing.T, path string) {
	t.Helper()

	var called bool
	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			called = true
			if zipFile != path {
				t.Fatalf("zip path = %q, want %q", zipFile, path)
			}
			return "Checking zip - OK", nil
		},
	}
	client := &Client{library: native}

	if _, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{Path: path}); err != nil {
		t.Fatalf("VerifyZIP returned error: %v", err)
	}
	if !called {
		t.Fatal("VerifyZIP did not call native")
	}
}

func assertZIPSignerCertificateReceivesPath(t *testing.T, path string) {
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

	if _, err := client.ZIPSignerCertificate(context.Background(), ZIPSignerCertificateRequest{Path: path}); err != nil {
		t.Fatalf("ZIPSignerCertificate returned error: %v", err)
	}
	if !called {
		t.Fatal("ZIPSignerCertificate did not call native")
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

func TestSignZIPRejectsDanglingSymlinkOutputBeforeNativeCall(t *testing.T) {
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

func TestSignZIPRejectsGroupWritableNativeOutputInNonPrivateOutputDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod output dir: %v", err)
	}

	inputPath := writeTestZIPInput(t, dir, "payload.txt")
	outputPath := filepath.Join(dir, "signed.zip")
	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			if err := os.WriteFile(outputPath, []byte("zip"), 0o600); err != nil {
				return err
			}

			return os.Chmod(outputPath, 0o660)
		},
	}
	client := &Client{library: native}

	_, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  inputPath,
		OutputPath: outputPath,
	})
	if err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("SignZIP error = %v, want group-writable output rejection", err)
	}
	if _, statErr := os.Lstat(outputPath); statErr != nil {
		t.Fatalf("group-writable output stat error = %v, want non-private output to remain", statErr)
	}
}

func TestSignZIPAllowsGroupWritableNativeOutputInPrivateOutputDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod output dir: %v", err)
	}

	inputPath := writeTestZIPInput(t, dir, "payload.txt")
	outputPath := filepath.Join(dir, "signed.zip")
	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			if err := os.WriteFile(outputPath, []byte("zip"), 0o600); err != nil {
				return err
			}

			return os.Chmod(outputPath, 0o660)
		},
	}
	client := &Client{library: native}

	signed, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  inputPath,
		OutputPath: outputPath,
	})
	if err != nil {
		t.Fatalf("SignZIP returned error: %v", err)
	}
	if signed.Path != outputPath {
		t.Fatalf("signed path = %q, want %q", signed.Path, outputPath)
	}
	if _, statErr := os.Lstat(outputPath); statErr != nil {
		t.Fatalf("group-writable output stat error = %v, want file to remain", statErr)
	}
}
