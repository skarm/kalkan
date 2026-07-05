package ckalkan_test

import (
	"os"
	"path/filepath"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestRealKalkanCryptSDKProvidedCMSAndZIP(t *testing.T) {
	assets := sdkAssetsForIntegration(t)
	client := newRealClient(t, realSDKBufferOptions()...)
	loadSDKCertificates(t, client, assets)

	cms := readSDKExample(t, assets, "test_CMS_GOST")
	verified, err := client.VerifyData(ckalkan.VerifyDataRequest{
		Flags:              ckalkan.SignCMS | ckalkan.InPEM | ckalkan.NoCheckCertTime,
		Signature:          cms,
		VerifyInfoCapacity: 1 << 20,
		DataCapacity:       1 << 20,
		CertCapacity:       1 << 20,
	})
	if err != nil {
		t.Fatalf("VerifyData(SDK CMS) failed: %v", err)
	}
	requireStringContains(t, "SDK CMS verify info", verified.VerifyInfo, "Verify - OK")
	requireStringContains(t, "SDK CMS verify info", verified.VerifyInfo, "CAdES-T")
	if len(verified.Data) == 0 {
		t.Fatal("VerifyData(SDK CMS) returned empty attached data")
	}

	if _, err := client.GetCertFromCMS(cms, 0, ckalkan.InPEM); err != nil {
		t.Fatalf("GetCertFromCMS(SDK CMS) failed: %v", err)
	}
	if _, err := client.GetTimeFromSig(cms, ckalkan.InPEM|ckalkan.NoCheckCertTime, 0); err == nil {
		t.Log("GetTimeFromSig accepted the historical SDK timestamp")
	} else {
		requireKalkanError(t, "GetTimeFromSig(SDK CMS)", err)
	}

	for _, zipPath := range assets.ZIPs {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			info, err := client.ZipConVerify(zipPath, ckalkan.NoCheckCertTime)
			if err != nil {
				t.Fatalf("ZipConVerify(%s) failed: %v", zipPath, err)
			}
			requireStringContains(t, "ZIP verify info", info, "Checking zip - OK")
			requireStringContains(t, "ZIP verify info", info, "Verify - OK")
			if _, err := client.GetCertFromZipFile(zipPath, ckalkan.NoCheckCertTime, 0); err != nil {
				t.Fatalf("GetCertFromZipFile(%s) failed: %v", zipPath, err)
			}
		})
	}
}

func TestRealKalkanCryptSDKZipSignAndExpectedErrors(t *testing.T) {
	assets := sdkAssetsForIntegration(t)
	client := newRealClient(t, realSDKBufferOptions()...)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, sdkTestPassword, chooseSDKStore(t, assets.P12), ""); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}

	badDigest := []byte{1, 2, 3}
	if _, err := client.SignHash("", ckalkan.SignCMS|ckalkan.OutBase64|ckalkan.NoCheckCertTime, badDigest); err == nil {
		t.Fatal("SignHash unexpectedly accepted an invalid digest length")
	} else {
		kalkanErr := requireKalkanError(t, "SignHash(short digest)", err)
		if kalkanErr.Code != ckalkan.ErrorInvalidDigestLen {
			t.Fatalf("SignHash(short digest) code = %v, want ErrorInvalidDigestLen", kalkanErr.Code)
		}
	}

	outDir := t.TempDir()
	inputPath := filepath.Join(outDir, "payload.txt")
	if err := os.WriteFile(inputPath, []byte("ckalkan SDK ZIP payload"), 0o644); err != nil {
		t.Fatalf("write ZIP payload: %v", err)
	}
	if err := client.ZipConSign(ckalkan.ZipConSignRequest{FilePath: inputPath, Name: "signed-by-sdk-key", OutDir: outDir, Flags: ckalkan.NoCheckCertTime}); err != nil {
		t.Fatalf("ZipConSign failed: %v", err)
	}
	if _, ok := firstExistingFile(filepath.Join(outDir, "signed-by-sdk-key"), filepath.Join(outDir, "signed-by-sdk-key.zip")); !ok {
		t.Fatalf("ZipConSign did not create output in %s", outDir)
	}

	if _, err := client.GetTokens(ckalkan.StoreKazToken); err == nil {
		t.Log("GetTokens(StoreKazToken) found a token in this environment")
	} else {
		requireKalkanError(t, "GetTokens(StoreKazToken)", err)
	}
	if _, err := client.GetCertificatesList(); err == nil {
		t.Log("GetCertificatesList returned certificate aliases")
	} else {
		requireKalkanError(t, "GetCertificatesList", err)
	}

	if _, err := client.UVerifyData(ckalkan.VerifyDataRequest{Flags: ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.DetachedData | ckalkan.NoCheckCertTime, Data: []byte("not-a-file"), Signature: []byte("not-a-signature")}); err == nil {
		t.Fatal("UVerifyData unexpectedly accepted invalid input")
	} else {
		requireKalkanError(t, "UVerifyData(invalid)", err)
	}
}
