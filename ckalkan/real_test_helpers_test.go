package ckalkan_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

const realTestAlias = "ckalkan-integration-test"

type pkcs12Fixture struct {
	Dir      string
	KeyPath  string
	CertPath string
	P12Path  string
	Password string
	Alias    string
	CertPEM  []byte
	Data     []byte
}

func newRealClient(t *testing.T, options ...ckalkan.Option) *ckalkan.Client {
	t.Helper()
	library := strings.TrimSpace(os.Getenv("KALKANCRYPT_LIBRARY"))
	if library == "" {
		t.Skip("set KALKANCRYPT_LIBRARY to run real KalkanCrypt integration tests")
	}

	allOptions := make([]ckalkan.Option, 0, 4+len(options))
	allOptions = append(allOptions,
		ckalkan.WithLibrary(library),
		ckalkan.WithBufferSize(128),
		ckalkan.WithListBufferSize(128),
		ckalkan.WithMaxBufferSize(1<<20),
	)
	allOptions = append(allOptions, options...)

	client, err := ckalkan.New(allOptions...)
	if err != nil {
		if errors.Is(err, ckalkan.ErrUnavailable) {
			t.Skip("test requires a build with a native KalkanCrypt loader")
		}
		t.Fatalf("New(%q) failed: %v", library, err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	})
	if err := client.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	return client
}

func requireOpenSSL(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl executable is required for generated PKCS#12 integration tests")
	}
	return path
}

func generatePKCS12Fixture(t *testing.T) pkcs12Fixture {
	t.Helper()
	openssl := requireOpenSSL(t)
	dir := t.TempDir()
	fixture := pkcs12Fixture{
		Dir:      dir,
		KeyPath:  filepath.Join(dir, "key.pem"),
		CertPath: filepath.Join(dir, "cert.pem"),
		P12Path:  filepath.Join(dir, "key.p12"),
		Password: "pass1234",
		Alias:    realTestAlias,
		Data:     []byte("hello from ckalkan integration test"),
	}

	run := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, openssl, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("openssl %s failed: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	run(
		"req", "-x509", "-newkey", "rsa:2048",
		"-keyout", fixture.KeyPath,
		"-out", fixture.CertPath,
		"-days", "2",
		"-nodes",
		"-subj", "/C=KZ/O=ckalkan-test/CN="+fixture.Alias+"/serialNumber=123456",
	)
	run(
		"pkcs12", "-export",
		"-inkey", fixture.KeyPath,
		"-in", fixture.CertPath,
		"-out", fixture.P12Path,
		"-password", "pass:"+fixture.Password,
		"-name", fixture.Alias,
	)

	certPEM, err := os.ReadFile(fixture.CertPath)
	if err != nil {
		t.Fatalf("read generated certificate: %v", err)
	}
	fixture.CertPEM = certPEM
	return fixture
}

func requireKalkanError(t *testing.T, name string, err error) *ckalkan.KalkanError {
	t.Helper()
	if err == nil {
		t.Fatalf("%s unexpectedly succeeded", name)
	}
	var kalkanErr *ckalkan.KalkanError
	if !errors.As(err, &kalkanErr) {
		t.Fatalf("%s returned non-Kalkan error: %T %v", name, err, err)
	}
	return kalkanErr
}

func requireContains(t *testing.T, name string, value []byte, substr string) {
	t.Helper()
	if !bytes.Contains(value, []byte(substr)) {
		t.Fatalf("%s = %q, want substring %q", name, value, substr)
	}
}

func requireStringContains(t *testing.T, name, value, substr string) {
	t.Helper()
	if !strings.Contains(value, substr) {
		t.Fatalf("%s = %q, want substring %q", name, value, substr)
	}
}

func requireParsePEMCertificate(t *testing.T, name string, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("%s is not PEM data", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return cert
}

func firstExistingFile(paths ...string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func explainSkipNoAssets(t *testing.T, where string) {
	t.Helper()
	t.Skip("no usable KalkanCrypt test assets found in " + where)
}
