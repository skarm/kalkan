//go:build linux && cgo

package kalkancrypt_test

import (
	"bytes"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestContextVerifyDataAndCMSHelpersWithSDKCMS(t *testing.T) {
	ctx := openContext(t)
	assets := sdkAssetsForIntegration(t)
	loadSDKCertificates(t, ctx, assets)

	cms := readSDKExample(t, assets, "test_CMS_GOST")
	verifyResult, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{
		Flags:        signCMS | inPEM | noCheckCertTime,
		Signature:    cms,
		DataCapacity: 1 << 20,
		InfoCapacity: 1 << 20,
		CertCapacity: 1 << 20,
	})
	verified := requireVerifyOK(t, "VerifyData(SDK CMS)", verifyResult, err)
	if !bytes.Contains(verified.Info, []byte("Verify - OK")) {
		t.Fatalf("VerifyData(SDK CMS) info = %q, want Verify - OK", verified.Info)
	}
	if len(verified.Data) == 0 {
		t.Fatal("VerifyData(SDK CMS) returned empty attached data")
	}

	certResult, err := ctx.GetCertFromCMS(cms, 0, inPEM, 1<<20)
	if err != nil {
		t.Fatalf("GetCertFromCMS(SDK CMS) returned Go error: %v", err)
	}
	if certResult.Code != kcrOK {
		t.Fatalf("GetCertFromCMS(SDK CMS) code = %#x, want %#x", certResult.Code, kcrOK)
	}
	if certResult.OutLen != len(certResult.Data) {
		t.Fatalf("GetCertFromCMS OutLen = %d, data length = %d", certResult.OutLen, len(certResult.Data))
	}

	code, timestamp := ctx.GetTimeFromSig(cms, inPEM|noCheckCertTime, 0)
	if timestamp <= 0 {
		t.Fatalf("GetTimeFromSig(SDK CMS) = (%#x, %d), want a positive timestamp from the timestamped CMS", code, timestamp)
	}
}
