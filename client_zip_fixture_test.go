package kalkan

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientZIPFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)
	if len(assets.ZIPs) == 0 {
		t.Skip("no ZIP fixture containers found")
	}

	for _, zipPath := range assets.ZIPs {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			verification := verifyZIPFixture(t, ctx, client, zipPath)
			if len(verification.SignerCert) != 0 {
				t.Fatal("VerifyZIP returned signer certificate without ReturnSignerCertificate")
			}
		})
	}
}

func TestClientZIPRejectsEmptySignerCertificate(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)
	if len(assets.ZIPs) == 0 {
		t.Skip("no ZIP fixture containers found")
	}

	for _, zipPath := range assets.ZIPs {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			_, err := client.VerifyZIP(ctx, VerifyZIPRequest{
				Path:                    copyZIPFixture(t, zipPath),
				ReturnSignerCertificate: true,
				CertificateTimeCheck:    SkipCertificateTimeCheck,
			})
			requireEmptyZIPSignerCertificateError(t, "VerifyZIP(ReturnSignerCertificate)", err)

			verifiedPath := copyZIPFixture(t, zipPath)
			_ = verifyZIPFixtureAtPath(t, ctx, client, verifiedPath)
			_, err = client.ZIPSignerCertificate(ctx, ZIPSignerCertificateRequest{
				Path:                 verifiedPath,
				CertificateTimeCheck: SkipCertificateTimeCheck,
			})
			requireEmptyZIPSignerCertificateError(t, "ZIPSignerCertificate", err)
		})
	}
}

func verifyZIPFixture(t *testing.T, ctx context.Context, client *Client, zipPath string) *ZIPVerification {
	t.Helper()

	return verifyZIPFixtureAtPath(t, ctx, client, copyZIPFixture(t, zipPath))
}

func verifyZIPFixtureAtPath(t *testing.T, ctx context.Context, client *Client, zipPath string) *ZIPVerification {
	t.Helper()

	verification, err := client.VerifyZIP(ctx, VerifyZIPRequest{
		Path:                 zipPath,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("VerifyZIP(%s) failed: %v", zipPath, err)
	}
	if !verification.Valid {
		t.Fatalf("VerifyZIP(%s) returned invalid result", zipPath)
	}
	requireContains(t, "ZIP verification", verification.Info, "Checking zip - OK")
	requireContains(t, "ZIP verification", verification.Info, "Verify - OK")

	return verification
}

func requireEmptyZIPSignerCertificateError(t *testing.T, name string, err error) {
	t.Helper()

	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "ZIP signer certificate output is empty") {
		t.Fatalf("%s error = %v, want empty signer certificate rejection", name, err)
	}
}
