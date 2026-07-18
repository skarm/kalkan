package kalkan

import (
	"context"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestCMSFixturesContainExpectedSigningTimes(t *testing.T) {
	tests := []struct {
		name      string
		wantTimes []time.Time
	}{
		{
			name: "test_CMS_GOST.txt",
			wantTimes: []time.Time{
				time.Date(2018, 12, 21, 9, 24, 0, 0, time.UTC),
				time.Date(2018, 12, 21, 9, 25, 4, 0, time.UTC),
			},
		},
		{
			name: "CMS_for_double_sign.txt",
			wantTimes: []time.Time{
				time.Date(2019, 8, 26, 6, 12, 23, 0, time.UTC),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "examples", test.name))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(data)
			if block == nil {
				t.Fatalf("%s is not PEM data", test.name)
			}

			gotTimes := collectASN1UTCTimes(block.Bytes)
			for _, want := range test.wantTimes {
				if !containsTime(gotTimes, want) {
					t.Fatalf("%s UTCTimes = %v, want %s", test.name, gotTimes, want)
				}
			}
		})
	}
}

func collectASN1UTCTimes(der []byte) []time.Time {
	var times []time.Time
	for len(der) != 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(der, &raw)
		if err != nil {
			return times
		}

		if raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagUTCTime {
			if parsed, ok := parseASN1UTCTime(raw.Bytes); ok {
				times = append(times, parsed)
			}
		}
		if raw.IsCompound {
			times = append(times, collectASN1UTCTimes(raw.Bytes)...)
		}

		der = rest
	}

	return times
}

func parseASN1UTCTime(value []byte) (time.Time, bool) {
	for _, layout := range []string{"060102150405Z0700", "060102150405Z"} {
		parsed, err := time.Parse(layout, string(value))
		if err == nil {
			return parsed.UTC(), true
		}
	}

	return time.Time{}, false
}

func containsTime(times []time.Time, want time.Time) bool {
	for _, got := range times {
		if got.Equal(want) {
			return true
		}
	}

	return false
}

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
