//go:build linux && cgo

package kalkancrypt_test

import (
	"bytes"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestContextVerifyDataAndCMSHelpersWithCMSFixture(t *testing.T) {
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

	certResult, err := ctx.GetCertFromCMS(cms, 0, inPEM, 1<<20)
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
