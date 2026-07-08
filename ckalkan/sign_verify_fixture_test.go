package ckalkan_test

import (
	"bytes"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestSignVerifyVariants(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixturePassword, chooseStore(t, assets.P12), ""); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}

	if err := client.SetProxy(ckalkan.ProxyRequest{Flags: ckalkan.ProxyOff}); err != nil {
		t.Fatalf("SetProxy(ProxyOff) failed: %v", err)
	}
	if err := client.SetTSAURL("http://test.pki.gov.kz/tsp/"); err != nil {
		t.Fatalf("SetTSAURL failed: %v", err)
	}

	data := readExample(t, assets, "text")
	if len(bytes.TrimSpace(data)) == 0 {
		data = []byte("ckalkan CMS fixture data")
	}

	variants := []struct {
		name        string
		signFlags   ckalkan.Flag
		verifyFlags ckalkan.Flag
		wantData    bool
	}{
		{name: "attached base64 CMS", signFlags: ckalkan.SignCMS | ckalkan.OutBase64 | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.NoCheckCertTime, wantData: true},
		{name: "attached DER CMS", signFlags: ckalkan.SignCMS | ckalkan.OutDER | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime, wantData: true},
		{name: "attached PEM CMS", signFlags: ckalkan.SignCMS | ckalkan.OutPEM | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignCMS | ckalkan.InPEM | ckalkan.NoCheckCertTime, wantData: true},
		{name: "detached base64 CMS", signFlags: ckalkan.SignCMS | ckalkan.OutBase64 | ckalkan.DetachedData | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.DetachedData | ckalkan.NoCheckCertTime},
		{name: "detached DER CMS", signFlags: ckalkan.SignCMS | ckalkan.OutDER | ckalkan.DetachedData | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.DetachedData | ckalkan.NoCheckCertTime},
		{name: "draft base64", signFlags: ckalkan.SignDraft | ckalkan.OutBase64 | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignDraft | ckalkan.InBase64 | ckalkan.NoCheckCertTime},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			sig, err := client.SignData("", variant.signFlags, data, nil)
			if err != nil {
				t.Fatalf("SignData failed: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("SignData returned empty data")
			}
			verified, err := client.VerifyData(ckalkan.VerifyDataRequest{
				Flags:              variant.verifyFlags,
				Data:               data,
				Signature:          sig,
				VerifyInfoCapacity: 1 << 20,
				DataCapacity:       1 << 20,
				CertCapacity:       1 << 20,
			})
			if err != nil {
				t.Fatalf("VerifyData failed: %v", err)
			}
			requireStringContains(t, "verify info", verified.VerifyInfo, "Verify - OK")
			if variant.wantData && !bytes.Equal(verified.Data, data) {
				t.Fatalf("VerifyData returned data %q, want %q", verified.Data, data)
			}
		})
	}

	gost512Digest := make([]byte, 64)
	for i := range gost512Digest {
		gost512Digest[i] = byte(i)
	}
	for _, flags := range []ckalkan.Flag{
		ckalkan.SignCMS | ckalkan.OutBase64 | ckalkan.NoCheckCertTime,
		ckalkan.SignCMS | ckalkan.OutDER | ckalkan.NoCheckCertTime,
		ckalkan.SignDraft | ckalkan.OutBase64 | ckalkan.NoCheckCertTime,
	} {
		sig, err := client.SignHash("", flags, gost512Digest)
		if err != nil {
			t.Fatalf("SignHash(%#x) failed: %v", flags, err)
		}
		if len(sig) == 0 {
			t.Fatalf("SignHash(%#x) returned empty data", flags)
		}
	}
}
