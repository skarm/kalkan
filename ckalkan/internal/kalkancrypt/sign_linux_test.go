//go:build linux && cgo

package kalkancrypt_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

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
