package ckalkan_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
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

const integrationTestAlias = "ckalkan-integration-test"

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

func newIntegrationClient(t *testing.T, options ...ckalkan.Option) *ckalkan.Client {
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
		Alias:    integrationTestAlias,
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

func requireCMSCryptographicRejection(t *testing.T, client *ckalkan.Client, request ckalkan.VerifyDataRequest, name string) {
	t.Helper()
	result, err := client.VerifyData(request)
	code := requireKalkanError(t, "VerifyData(changed "+name+")", err).Code
	// The SDK exposes its OpenSSL failures as native numeric codes.
	if code != ckalkan.ErrorCode(0x8006E07B) && code != ckalkan.ErrorCode(0x2E09A09E) && uint64(code)>>24 != 4 {
		t.Fatalf("changed %s: got %s (%v), want signature/digest verification failure", name, code.Hex(), err)
	}
	if len(result.Data) != 0 || len(result.Cert) != 0 || result.VerifyInfo != "" {
		t.Fatalf("changed %s leaked successful output: %+v", name, result)
	}
}

func verifyOpenSSLCMS(t *testing.T, cms, payload []byte, detached, valid bool) {
	t.Helper()
	dir := t.TempDir()
	signaturePath, dataPath, outputPath := filepath.Join(dir, "signature.der"), filepath.Join(dir, "payload"), filepath.Join(dir, "verified")
	for path, data := range map[string][]byte{signaturePath: cms, dataPath: payload} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"cms", "-verify", "-binary", "-noverify", "-inform", "DER", "-in", signaturePath, "-out", outputPath}
	if detached {
		args = append(args, "-content", dataPath)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, requireOpenSSL(t), args...).CombinedOutput()
	if ctx.Err() != nil || (err == nil) != valid {
		t.Fatalf("OpenSSL verification: valid=%v error=%v context=%v\n%s", valid, err, ctx.Err(), output)
	}
	if valid {
		verified, err := os.ReadFile(outputPath)
		if err != nil || !bytes.Equal(verified, payload) {
			t.Fatalf("OpenSSL recovered payload = %x, %v; want %x", verified, err, payload)
		}
	} else if !bytes.Contains(output, []byte("CMS Verification failure")) {
		t.Fatalf("OpenSSL failed without a cryptographic rejection: %s", output)
	}
}

func cmsTimestampToken(t *testing.T, cms []byte) []byte {
	t.Helper()
	var envelope struct {
		OID     asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(cms, &envelope); err != nil {
		t.Fatal(err)
	}
	var content struct {
		Version      int
		Digests      asn1.RawValue
		Content      asn1.RawValue
		Certificates asn1.RawValue   `asn1:"optional,tag:0"`
		Revocations  asn1.RawValue   `asn1:"optional,tag:1"`
		Signers      []asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(envelope.Content.Bytes, &content); err != nil || len(content.Signers) != 1 {
		t.Fatalf("timestamped CMS signer: %v", err)
	}
	var signer struct {
		Version    int
		Identifier asn1.RawValue
		Digest     asn1.RawValue
		Attributes asn1.RawValue `asn1:"optional,tag:0"`
		Algorithm  asn1.RawValue
		Signature  []byte
		Unsigned   asn1.RawValue `asn1:"optional,tag:1"`
	}
	if _, err := asn1.Unmarshal(content.Signers[0].FullBytes, &signer); err != nil {
		t.Fatal(err)
	}
	for remaining := signer.Unsigned.Bytes; len(remaining) > 0; {
		var attribute struct {
			OID    asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		rest, err := asn1.Unmarshal(remaining, &attribute)
		if err != nil {
			t.Fatal(err)
		}
		if attribute.OID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}) && len(attribute.Values) == 1 {
			return attribute.Values[0].FullBytes
		}
		remaining = rest
	}
	t.Fatal("CMS has no signatureTimeStampToken unsigned attribute")
	return nil
}
