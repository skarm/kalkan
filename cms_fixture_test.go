package kalkan

import (
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
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
