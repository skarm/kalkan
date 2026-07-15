package kalkan

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyZIPFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)
	if len(assets.ZIPs) == 0 {
		t.Skip("no ZIP fixture containers found")
	}

	for _, zipPath := range assets.ZIPs {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			verifyZIPFixture(t, ctx, client, zipPath)
		})
	}
}

func TestExtractZIPSignerCertificateFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)
	if len(assets.ZIPs) == 0 {
		t.Skip("no ZIP fixture containers found")
	}

	for _, zipPath := range assets.ZIPs {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			cert, err := client.ExtractZIPSignerCertificate(ctx, ExtractZIPSignerCertificateRequest{
				Path:                 copyZIPFixture(t, zipPath),
				CertificateTimeCheck: SkipCertificateTimeCheck,
			})
			if err != nil {
				if errors.Is(err, ErrInvalidInput) && strings.Contains(err.Error(), "ZIP signer certificate output is empty") {
					return
				}

				t.Fatalf("ExtractZIPSignerCertificate(%s) failed: %v", zipPath, err)
			}
			if isEmptyNativeCertificate(cert) {
				t.Fatal("ExtractZIPSignerCertificate returned an empty certificate without an error")
			}
		})
	}
}

func verifyZIPFixture(t *testing.T, ctx context.Context, client *Client, zipPath string) {
	t.Helper()

	verification, err := client.VerifyZIP(ctx, VerifyZIPRequest{
		Path:                 copyZIPFixture(t, zipPath),
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("VerifyZIP(%s) failed: %v", zipPath, err)
	}
	requireContains(t, "ZIP verification", verification.Info, "Checking zip - OK")
	requireContains(t, "ZIP verification", verification.Info, "Verify - OK")
}
