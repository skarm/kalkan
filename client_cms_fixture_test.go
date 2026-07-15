package kalkan

import (
	"context"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestVerifyCMSFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)

	t.Run("attached timestamped CMS", func(t *testing.T) {
		cms := readFixtureExample(t, assets, "test_CMS_GOST")
		verification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
			Signature:            PEM(cms),
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("VerifyCMS(test_CMS_GOST) failed: %v", err)
		}
		requireContains(t, "test_CMS_GOST verification", verification.Info, "Verify - OK")
		requireContains(t, "test_CMS_GOST verification", verification.Info, "CAdES-T")
		if len(verification.Data) == 0 {
			t.Fatal("VerifyCMS(test_CMS_GOST) returned empty attached data")
		}

		if _, err := client.GetTimeFromSig(ctx, PEM(cms)); err == nil {
			t.Fatal("GetTimeFromSig(test_CMS_GOST) unexpectedly succeeded for expired CMS fixture fixture")
		} else {
			requireKalkanError(t, "GetTimeFromSig(test_CMS_GOST)", err)
		}
	})

	t.Run("detached CMS without data", func(t *testing.T) {
		cms := readFixtureExample(t, assets, "CMS_for_double_sign")
		if _, err := client.GetTimeFromSig(ctx, PEM(cms)); !isKalkanErrorCode(err, ckalkan.ErrorNoTSAToken) {
			t.Fatalf("GetTimeFromSig(CMS_for_double_sign) error = %v, want ErrorNoTSAToken", err)
		}
		if _, err := client.VerifyCMS(ctx, VerifyCMSRequest{
			Signature:            PEM(cms),
			CertificateTimeCheck: SkipCertificateTimeCheck,
		}); err == nil {
			t.Fatal("VerifyCMS(CMS_for_double_sign without detached data) unexpectedly succeeded")
		} else {
			requireKalkanError(t, "VerifyCMS(CMS_for_double_sign without detached data)", err)
		}
	})
}
