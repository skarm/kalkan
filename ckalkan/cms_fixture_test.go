package ckalkan_test

import (
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestCMSFixtures(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	loadCertificates(t, client, assets)

	t.Run("attached timestamped CMS", func(t *testing.T) {
		cms := readExample(t, assets, "test_CMS_GOST")
		verified, err := client.VerifyData(ckalkan.VerifyDataRequest{
			Flags:              ckalkan.SignCMS | ckalkan.InPEM | ckalkan.NoCheckCertTime,
			Signature:          cms,
			VerifyInfoCapacity: 1 << 20,
			DataCapacity:       1 << 20,
			CertCapacity:       1 << 20,
		})
		if err != nil {
			t.Fatalf("VerifyData(CMS fixture) failed: %v", err)
		}
		requireStringContains(t, "CMS fixture verify info", verified.VerifyInfo, "Verify - OK")
		requireStringContains(t, "CMS fixture verify info", verified.VerifyInfo, "CAdES-T")
		if len(verified.Data) == 0 {
			t.Fatal("VerifyData(CMS fixture) returned empty attached data")
		}

		if _, err := client.GetCertFromCMS(cms, 0, ckalkan.InPEM); err != nil {
			t.Fatalf("GetCertFromCMS(CMS fixture) failed: %v", err)
		}
		if _, err := client.GetTimeFromSig(cms, ckalkan.InPEM|ckalkan.NoCheckCertTime, 0); err == nil {
			t.Fatal("GetTimeFromSig(CMS fixture) unexpectedly succeeded for expired CMS fixture fixture")
		} else {
			requireKalkanError(t, "GetTimeFromSig(CMS fixture)", err)
		}
	})

	t.Run("detached CMS without data", func(t *testing.T) {
		cms := readExample(t, assets, "CMS_for_double_sign")
		if _, err := client.GetCertFromCMS(cms, 0, ckalkan.InPEM); err != nil {
			t.Fatalf("GetCertFromCMS(CMS_for_double_sign) failed: %v", err)
		}
		if _, err := client.GetTimeFromSig(cms, ckalkan.InPEM|ckalkan.NoCheckCertTime, 0); err == nil {
			t.Fatal("GetTimeFromSig(CMS_for_double_sign) unexpectedly found a timestamp")
		} else if kalkanErr := requireKalkanError(t, "GetTimeFromSig(CMS_for_double_sign)", err); kalkanErr.Code != ckalkan.ErrorNoTSAToken {
			t.Fatalf("GetTimeFromSig(CMS_for_double_sign) code = %v, want ErrorNoTSAToken", kalkanErr.Code)
		}
		if _, err := client.VerifyData(ckalkan.VerifyDataRequest{
			Flags:              ckalkan.SignCMS | ckalkan.InPEM | ckalkan.NoCheckCertTime,
			Signature:          cms,
			VerifyInfoCapacity: 1 << 20,
			DataCapacity:       1 << 20,
			CertCapacity:       1 << 20,
		}); err == nil {
			t.Fatal("VerifyData(CMS_for_double_sign without detached data) unexpectedly succeeded")
		} else {
			requireKalkanError(t, "VerifyData(CMS_for_double_sign without detached data)", err)
		}
	})
}
