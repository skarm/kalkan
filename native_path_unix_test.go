//go:build darwin || linux

package kalkan

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestLoadKeyStorePassesFIFOPathToNative(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "key.p12")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	native := &fakeNative{
		loadKeyStoreFunc: func(storage ckalkan.Store, password, container, alias string) error {
			if container != fifoPath {
				t.Fatalf("container = %q, want %q", container, fifoPath)
			}
			return nil
		},
	}
	client := &Client{library: native}

	err := client.LoadKeyStore(context.Background(), KeyStore{
		Type: PKCS12,
		Path: fifoPath,
	})
	if err != nil {
		t.Fatalf("LoadKeyStore returned error: %v", err)
	}
}

func TestLoadTrustedCertificatePassesFIFOPathToNative(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "ca.pem")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	native := &fakeNative{
		loadCertFileFunc: func(path string, certType ckalkan.CertType) error {
			if path != fifoPath {
				t.Fatalf("path = %q, want %q", path, fifoPath)
			}
			return nil
		},
	}
	client := &Client{library: native}

	err := client.LoadTrustedCertificate(context.Background(), TrustedCertificate{
		Path: fifoPath,
		Type: CertificateCA,
	})
	if err != nil {
		t.Fatalf("LoadTrustedCertificate returned error: %v", err)
	}
}

func TestValidateCertificatePassesCRLFIFOPathToNative(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "cert.crl")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	native := &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			if req.ValidationPath != fifoPath {
				t.Fatalf("RevocationSource = %q, want %q", req.ValidationPath, fifoPath)
			}
			return ckalkan.ValidateCertificateResult{Info: "ok"}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate:      Bytes([]byte("cert")),
		Mode:             CertificateValidationCRL,
		RevocationSource: fifoPath,
	})
	if err != nil {
		t.Fatalf("ValidateCertificate returned error: %v", err)
	}
}
