//go:build linux && amd64 && cgo

package kalkancrypt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadBase64HashFileRejectsInvalidPathAndOversizedInput(t *testing.T) {
	if _, err := readBase64HashFile("file\x00other"); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("embedded NUL: %v, want path rejection", err)
	}
	path := filepath.Join(t.TempDir(), "oversized.b64")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 1<<31); err != nil {
		t.Fatal(err)
	}
	if _, err := readBase64HashFile(path); err == nil || !strings.Contains(err.Error(), "overflows native C int") {
		t.Fatalf("oversized file: %v, want length rejection before allocation", err)
	}
}

func TestLinuxZIPSignRejectsNonDirectoryBeforeNativeCall(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(file, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "payload-link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	driver := &linuxDriver{}
	for _, input := range []string{file, link, filepath.Join(dir, "missing"), os.DevNull} {
		if code := driver.ZipConSign(ZipConSignCall{FilePath: input, Name: "signed", OutDir: dir}); code != errorParam {
			t.Fatalf("ZipConSign(%q) = %#x, want parameter error before native call", input, code)
		}
	}
	// A valid directory must reach the native bridge.
	// Its nil function table returns LibraryNotInitialized, which distinguishes
	// it from the input guard.
	if code := driver.ZipConSign(ZipConSignCall{FilePath: dir, Name: "signed", OutDir: dir}); code != errorLibraryNotInitialized {
		t.Fatalf("ZipConSign(directory) = %#x, want native bridge call", code)
	}
}

func TestLinuxVerifySmallBuffersRequestRetryBeforeNativeCall(t *testing.T) {
	for _, test := range []struct {
		name               string
		info, cert         int
		wantInfo, wantCert int
	}{
		{name: "info", info: 1, cert: 8192, wantInfo: 4096},
		{name: "certificate", info: 4096, cert: 1, wantCert: 8192},
		{name: "both", info: 1, cert: 1, wantInfo: 4096, wantCert: 8192},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A nil function table would return LibraryNotInitialized if called.
			driver := &linuxDriver{}
			for _, universal := range []bool{false, true} {
				result, err := driver.verifyData(VerifyDataCall{
					DataCapacity: 1, InfoCapacity: test.info, CertCapacity: test.cert, CertID: 1,
				}, universal)
				if err != nil || result.Code != 0x08f00005 || result.InfoLen != test.wantInfo || result.CertLen != test.wantCert ||
					result.Data != nil || result.Info != nil || result.Cert != nil {
					t.Fatalf("universal=%v: result=%+v, err=%v, want bounded retry without output", universal, result, err)
				}
			}
		})
	}
}

func TestLinuxDriverCloseHandlesNilHandle(t *testing.T) {
	var nilDriver *linuxDriver
	if err := nilDriver.Close(); err != nil {
		t.Fatalf("nil driver Close returned error: %v", err)
	}

	if err := (&linuxDriver{}).Close(); err != nil {
		t.Fatalf("empty driver Close returned error: %v", err)
	}
}

func TestDLErrorStringReturnsFallback(t *testing.T) {
	if got := dlerrorString("fallback error"); got != "fallback error" {
		t.Fatalf("dlerrorString fallback = %q, want fallback error", got)
	}
}

func TestCStringRejectsEmbeddedNUL(t *testing.T) {
	ptr, free, err := cString("bad\x00value")
	if err == nil {
		if free != nil {
			free()
		}
		t.Fatalf("cString returned ptr=%v, want embedded NUL error", ptr)
	}
}

func TestPointerHelpersReturnNilForEmptyBuffers(t *testing.T) {
	if ptr := charPtr(nil); ptr != nil {
		t.Fatalf("charPtr(nil) = %v, want nil", ptr)
	}
	if ptr := ucharPtr(nil); ptr != nil {
		t.Fatalf("ucharPtr(nil) = %v, want nil", ptr)
	}
	if ptr := charPtr([]byte("x")); ptr == nil {
		t.Fatal("charPtr(non-empty) returned nil")
	}
	if ptr := ucharPtr([]byte("x")); ptr == nil {
		t.Fatal("ucharPtr(non-empty) returned nil")
	}
}
