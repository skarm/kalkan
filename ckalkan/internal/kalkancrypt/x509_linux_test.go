//go:build linux && cgo

package kalkancrypt_test

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestContextX509LoadCertificateFromFileAndBuffer(t *testing.T) {
	ctx := openContext(t)
	assets := sdkAssetsForIntegration(t)
	if len(assets.certs) == 0 {
		t.Skip("no SDK certificate fixtures found")
	}

	certPath := assets.certs[0]
	certType := certUser
	lowerName := strings.ToLower(filepath.Base(certPath))
	switch {
	case strings.Contains(lowerName, "root"):
		certType = certCA
	case strings.Contains(lowerName, "nca"):
		certType = certInter
	}
	if code := ctx.X509LoadCertificateFromFile(certPath, certType); code != kcrOK {
		t.Fatalf("X509LoadCertificateFromFile(%s) = %#x, want %#x", certPath, code, kcrOK)
	}

	certPEMData := readSDKExample(t, assets, "test_CERT_GOST")
	if code := ctx.X509LoadCertificateFromBuffer(certPEMData, certPEM); code != kcrOK {
		t.Fatalf("X509LoadCertificateFromBuffer(test_CERT_GOST) = %#x, want %#x", code, kcrOK)
	}

	infoResult, err := ctx.X509CertificateGetInfo(certPEMData, certPropSignatureAlg, 1<<20)
	info := requireBufferOK(t, "X509CertificateGetInfo(SignatureAlg)", infoResult, err)
	if len(bytes.TrimSpace(info)) == 0 {
		t.Fatal("X509CertificateGetInfo(SignatureAlg) returned only whitespace")
	}
}

func TestContextX509ValidateCertificateReturnsNativeResultForRealCertificate(t *testing.T) {
	ctx := openContext(t)
	assets := sdkAssetsForIntegration(t)
	if len(assets.certs) == 0 {
		t.Skip("no SDK certificate fixtures found")
	}

	cert := readFile(t, assets.certs[0])
	result, err := ctx.X509ValidateCertificate(kalkancrypt.ValidateCertificateCall{
		Certificate:    cert,
		ValidationType: useNothing,
		ValidationPath: filepath.Join(assets.root, "certs"),
		Flags:          noCheckCertTime,
		InfoCapacity:   1 << 20,
		OCSPCapacity:   1 << 20,
	})
	if err != nil {
		t.Fatalf("X509ValidateCertificate returned Go error: %v", err)
	}
	if result.InfoLen != len(result.Info) {
		t.Fatalf("X509ValidateCertificate InfoLen = %d, data length = %d", result.InfoLen, len(result.Info))
	}
	if result.OCSPLen != len(result.OCSP) {
		t.Fatalf("X509ValidateCertificate OCSPLen = %d, data length = %d", result.OCSPLen, len(result.OCSP))
	}
	if result.Code != kcrOK && len(result.Info) == 0 {
		t.Fatalf("X509ValidateCertificate code = %#x with empty diagnostic info", result.Code)
	}
}
