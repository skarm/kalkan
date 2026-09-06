//go:build linux && amd64 && cgo

package kalkancrypt_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestCMSFixtureOperations(t *testing.T) {
	ctx := openContext(t)
	assets := loadFixtureAssets(t)
	loadCertificates(t, ctx, assets)

	cms := readExample(t, assets, "test_CMS_GOST")
	verifyResult, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{
		Flags:        signCMS | inPEM | noCheckCertTime,
		Signature:    cms,
		DataCapacity: 1 << 20,
		InfoCapacity: 1 << 20,
		CertCapacity: 1 << 20,
	})
	verified := requireVerifyOK(t, "VerifyData(CMS fixture)", verifyResult, err)
	if !bytes.Contains(verified.Info, []byte("Verify - OK")) {
		t.Fatalf("VerifyData(CMS fixture) info = %q, want Verify - OK", verified.Info)
	}
	if len(verified.Data) == 0 {
		t.Fatal("VerifyData(CMS fixture) returned empty attached data")
	}

	certResult, err := ctx.GetCertFromCMS(kalkancrypt.GetCertFromCMSCall{
		CMS:      cms,
		Flags:    inPEM,
		Capacity: 1 << 20,
	})
	if err != nil {
		t.Fatalf("GetCertFromCMS(CMS fixture) returned Go error: %v", err)
	}
	if certResult.Code != kcrOK {
		t.Fatalf("GetCertFromCMS(CMS fixture) code = %#x, want %#x", certResult.Code, kcrOK)
	}
	if certResult.OutLen != len(certResult.Data) {
		t.Fatalf("GetCertFromCMS OutLen = %d, data length = %d", certResult.OutLen, len(certResult.Data))
	}

	code, timestamp := ctx.GetTimeFromSig(cms, inPEM|noCheckCertTime, 0)
	if code == kcrOK {
		t.Fatal("GetTimeFromSig(CMS fixture) unexpectedly returned KCR_OK for expired CMS fixture fixture")
	}
	if timestamp <= 0 {
		t.Fatalf("GetTimeFromSig(CMS fixture) = (%#x, %d), want a positive timestamp with a non-OK warning code", code, timestamp)
	}
}

func TestContextSignDataDetachedCMS(t *testing.T) {
	ctx := openContext(t)
	loadPKCS12Fixture(t, ctx)

	certResult, err := ctx.X509ExportCertificateFromStore("", certPEM, 1<<20)
	cert := requireBufferOK(t, "X509ExportCertificateFromStore", certResult, err)
	if !bytes.Contains(cert, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Fatalf("exported certificate is not PEM: %q", cert[:min(len(cert), 64)])
	}

	commonNameResult, err := ctx.X509CertificateGetInfo(cert, certPropSubjectCommonName, 1<<20)
	commonName := requireBufferOK(t, "X509CertificateGetInfo(CommonName)", commonNameResult, err)
	if len(bytes.TrimSpace(commonName)) == 0 {
		t.Fatal("X509CertificateGetInfo(CommonName) returned only whitespace")
	}

	data := []byte("kalkancrypt low-level detached CMS roundtrip")
	signResult, err := ctx.SignData(kalkancrypt.SignDataCall{
		Flags:    signCMS | outBase64 | detachedData | noCheckCertTime,
		Data:     data,
		Capacity: 1 << 20,
	})
	signature := requireBufferOK(t, "SignData(detached CMS)", signResult, err)

	verifyResult, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{
		Flags:        signCMS | inBase64 | detachedData | noCheckCertTime,
		Data:         data,
		Signature:    signature,
		DataCapacity: 1 << 20,
		InfoCapacity: 1 << 20,
		CertCapacity: 1 << 20,
	})
	verified := requireVerifyOK(t, "VerifyData(detached CMS)", verifyResult, err)
	if !bytes.Contains(verified.Info, []byte("Verify - OK")) {
		t.Fatalf("VerifyData info = %q, want Verify - OK", verified.Info)
	}
}

func TestContextSignHashNativeResult(t *testing.T) {
	ctx := openContext(t)
	loadPKCS12Fixture(t, ctx)

	digest := make([]byte, 64)
	for i := range digest {
		digest[i] = byte(i)
	}
	signedHashResult, err := ctx.SignHash(kalkancrypt.SignHashCall{
		Flags:    signCMS | outBase64 | noCheckCertTime,
		Hash:     digest,
		Capacity: 1 << 20,
	})
	signedHash := requireBufferOK(t, "SignHash(CMS)", signedHashResult, err)
	if len(bytes.TrimSpace(signedHash)) == 0 {
		t.Fatal("SignHash(CMS) returned only whitespace")
	}
}

func TestContextUVerifyDataAutoDetectsAttachedCMSFile(t *testing.T) {
	ctx := openContext(t)
	loadPKCS12Fixture(t, ctx)

	data := []byte("kalkancrypt low-level UVerifyData attached CMS roundtrip")
	signResult, err := ctx.SignData(kalkancrypt.SignDataCall{
		Flags:    signCMS | outBase64 | noCheckCertTime,
		Data:     data,
		Capacity: 1 << 20,
	})
	signature := requireBufferOK(t, "SignData(attached CMS)", signResult, err)
	signaturePath := filepath.Join(t.TempDir(), "attached.cms")
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatalf("write attached CMS: %v", err)
	}

	verifyResult, err := ctx.UVerifyData(kalkancrypt.VerifyDataCall{
		// UVerifyData reads the file and auto-detects CMS/base64; no format flag
		// is intentionally supplied here.
		Flags:        noCheckCertTime,
		Data:         data,
		Signature:    []byte(signaturePath),
		DataCapacity: 1 << 20,
		InfoCapacity: 1 << 20,
		CertCapacity: 1 << 20,
	})
	verifyResult = requireVerifyOK(t, "UVerifyData(attached CMS file)", verifyResult, err)
	if verifyResult.DataLen != len(verifyResult.Data) {
		t.Fatalf("UVerifyData DataLen = %d, data length = %d", verifyResult.DataLen, len(verifyResult.Data))
	}
	if verifyResult.InfoLen != len(verifyResult.Info) {
		t.Fatalf("UVerifyData InfoLen = %d, info length = %d", verifyResult.InfoLen, len(verifyResult.Info))
	}
	if verifyResult.CertLen != len(verifyResult.Cert) {
		t.Fatalf("UVerifyData CertLen = %d, cert length = %d", verifyResult.CertLen, len(verifyResult.Cert))
	}
	if !bytes.Contains(verifyResult.Info, []byte("Verify - OK")) {
		t.Fatalf("UVerifyData info = %q, want Verify - OK", verifyResult.Info)
	}
	if !bytes.Equal(verifyResult.Data, data) {
		t.Fatalf("UVerifyData data = %q, want %q", verifyResult.Data, data)
	}
}
