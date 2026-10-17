package javakalkan_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/kalkan"
)

func TestJavaZIPRejectsLocalPathMismatch(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := openJavaIntegrationClient(t, javaIntegrationTrust(t, assets)...)
	valid := fixturePath("zip", "native_gost512_interop.zip")
	if _, err := client.VerifyZIP(t.Context(), kalkan.VerifyZIPRequest{Path: valid, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(valid)
	if err != nil {
		t.Fatal(err)
	}
	// Only the local header changes: the central directory, payload, signed
	// manifest and CMS remain untouched. Streaming extractors see traversal.
	position := bytes.Index(data, []byte("java_document.txt"))
	if position < 30 || !bytes.Equal(data[position-30:position-26], []byte("PK\x03\x04")) {
		t.Fatal("fixture local header not found")
	}
	copy(data[position:], ".././document.txt")
	path := javaIntegrationFile(t, "mismatched.zip", data)
	if _, err := client.VerifyZIP(t.Context(), kalkan.VerifyZIPRequest{Path: path, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}); !errors.Is(err, kalkan.ErrInvalidInput) {
		t.Fatalf("unsigned local path change accepted: %v", err)
	}
}

func javaZIPEntries(t *testing.T, filename string) map[string][]byte {
	t.Helper()
	r, err := zip.OpenReader(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	entries := make(map[string][]byte)
	for _, f := range r.File {
		input, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(input)
		_ = input.Close()
		if err != nil {
			t.Fatal(err)
		}
		entries[f.Name] = data
	}
	return entries
}

func javaZIPFile(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	var encoded bytes.Buffer
	w := zip.NewWriter(&encoded)
	for name, data := range entries {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		// Malicious directory attributes must not hide a file from verification.
		if name == "unsigned-directory.txt" {
			header.SetMode(os.ModeDir | 0o755)
		}
		f, err := w.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return javaIntegrationFile(t, "input.zip", encoded.Bytes())
}

func TestJavaZIPContainers(t *testing.T) {
	requireJavaValidationProvider(t)
	pki := newJavaValidationPKI(t, "http://unused.invalid")
	client := openJavaIntegrationClient(t, append(pki.trust(t), kalkan.WithAtomicZIPOutput())...)
	store := javaValidationKeyStore(t, pki.leaf)
	if err := client.LoadKeyStore(t.Context(), kalkan.KeyStore{Path: store, Password: "test-password"}); err != nil {
		t.Fatal(err)
	}
	input := javaIntegrationFile(t, "payload.txt", []byte("ZIP payload: документ\x00\xff"))
	other := javaIntegrationFile(t, "second.txt", []byte("another payload"))
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "nested", "документ.txt"), []byte("nested data"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsigned := javaZIPFile(t, map[string][]byte{"plain.txt": []byte("unsigned archive input")})
	for _, tc := range []struct {
		name, input string
		files       int
	}{
		{"file", input, 1}, {"file list", input + "|" + other + "|", 2}, {"directory", directory, 1}, {"unsigned ZIP", unsigned, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "signed.ZIP")
			signed, err := client.SignZIP(t.Context(), kalkan.SignZIPRequest{InputPath: tc.input, OutputPath: output})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.VerifyZIP(t.Context(), kalkan.VerifyZIPRequest{Path: signed.Path}); err != nil {
				t.Fatal(err)
			}
			entries := javaZIPEntries(t, signed.Path)
			if len(entries) != tc.files+2 {
				t.Fatalf("entries=%d, want %d", len(entries), tc.files+2)
			}
			cert, err := client.ExtractZIPSignerCertificate(t.Context(), kalkan.ExtractZIPSignerCertificateRequest{Path: signed.Path, SignerID: 1})
			if err != nil || !bytes.Equal(cert, pki.leaf.cert.Raw) {
				t.Fatalf("signer certificate differs: %v", err)
			}
			if _, err := client.SignZIP(t.Context(), kalkan.SignZIPRequest{InputPath: input, OutputPath: output}); err == nil {
				t.Fatal("overwrote existing output")
			}
		})
	}
	// Subtest temporary directories end with the subtest, so sign a retained container.
	signed, err := client.SignZIP(t.Context(), kalkan.SignZIPRequest{InputPath: input, OutputPath: filepath.Join(t.TempDir(), "one.zip")})
	if err != nil {
		t.Fatal(err)
	}
	signedPath := signed.Path
	secondStore := javaValidationKeyStore(t, pki.responder)
	if err := client.LoadKeyStore(t.Context(), kalkan.KeyStore{Path: secondStore, Password: "test-password"}); err != nil {
		t.Fatal(err)
	}
	appended, err := client.SignZIP(t.Context(), kalkan.SignZIPRequest{InputPath: signedPath + "|", OutputPath: filepath.Join(t.TempDir(), "two.zip")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyZIP(t.Context(), kalkan.VerifyZIPRequest{Path: appended.Path}); err != nil {
		t.Fatal(err)
	}
	certs := make(map[string]bool)
	for i := 1; i <= 2; i++ {
		cert, err := client.ExtractZIPSignerCertificate(t.Context(), kalkan.ExtractZIPSignerCertificateRequest{Path: appended.Path, SignerID: i})
		if err != nil {
			t.Fatal(err)
		}
		certs[string(cert)] = true
	}
	if !certs[string(pki.leaf.cert.Raw)] || !certs[string(pki.responder.cert.Raw)] {
		t.Fatal("append lost an original signer")
	}
	if _, err := client.ExtractZIPSignerCertificate(t.Context(), kalkan.ExtractZIPSignerCertificateRequest{Path: appended.Path, SignerID: 3}); err == nil {
		t.Fatal("nonexistent signer accepted")
	}
	for _, fault := range []string{"payload", "manifest", "signature", "unsigned extra", "missing payload", "unsafe path", "directory attributes"} {
		t.Run(fault, func(t *testing.T) {
			entries := javaZIPEntries(t, appended.Path)
			switch fault {
			case "payload":
				entries["payload.txt"][0] ^= 1
			case "manifest":
				entries["META-INF/NCAManifest.xml"] = append(entries["META-INF/NCAManifest.xml"], '\n')
			case "signature":
				for name := range entries {
					if strings.HasSuffix(name, ".cms") {
						entries[name][len(entries[name])-1] ^= 1
					}
				}
			case "unsigned extra":
				entries["extra.txt"] = []byte("not signed")
			case "missing payload":
				delete(entries, "payload.txt")
			case "directory attributes":
				entries["unsigned-directory.txt"] = []byte("UNSIGNED ATTACKER PAYLOAD")
			case "unsafe path":
				entries["../outside.txt"] = []byte("outside")
			}
			path := javaZIPFile(t, entries)
			if _, err := client.VerifyZIP(t.Context(), kalkan.VerifyZIPRequest{Path: path}); err == nil {
				t.Fatal("invalid archive accepted")
			}
			output := filepath.Join(t.TempDir(), "rejected.zip")
			if _, err := client.SignZIP(t.Context(), kalkan.SignZIPRequest{InputPath: path, OutputPath: output}); err == nil {
				t.Fatal("appended to invalid archive")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("failed signing left an output: %v", err)
			}
		})
	}
}

func TestJavaZIPNativeCompatibility(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := openJavaIntegrationClient(t, javaIntegrationTrust(t, assets)...)
	path := fixturePath("zip", "native_gost512_interop.zip")
	if _, err := client.VerifyZIP(t.Context(), kalkan.VerifyZIPRequest{Path: path, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}); err != nil {
		t.Fatal(err)
	}
	entries := javaZIPEntries(t, path)
	if !bytes.Equal(entries["java_document.txt"], []byte("abc")) {
		t.Fatal("native payload changed")
	}
}
