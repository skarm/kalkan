package kalkan

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/internal/testfixture"
)

const (
	fixturePassword = "Qwerty12"
	defaultAssetDir = "testdata"
	testTSAURL      = "http://test.pki.gov.kz/tsp/"
	testOCSPURL     = "http://test.pki.gov.kz/ocsp/"
)

type fixtureAssets = testfixture.SDKAssets

func openFixtureClient(t *testing.T, assets fixtureAssets) *Client {
	t.Helper()

	session := strings.TrimSpace(os.Getenv("KALKANCRYPT_LIBRARY"))
	if session == "" {
		t.Skip("set KALKANCRYPT_LIBRARY to run native-backed root API tests")
	}

	client, err := Open(context.Background(),
		WithLibraryPath(session),
		WithTSAURL(testTSAURL),
		WithOCSPURL(testOCSPURL),
		WithTrustedCertificate(TrustedCertificate{
			Path: certificatePath(t, assets, "root_test_gost_2022"),
			Type: CertificateCA,
		}),
		WithTrustedCertificate(TrustedCertificate{
			Path: certificatePath(t, assets, "nca_gost2022_test"),
			Type: CertificateIntermediate,
		}),
	)
	if errors.Is(err, ckalkan.ErrUnavailable) {
		t.Skip("native-backed root API tests require Linux with cgo enabled")
	}
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	})

	return client
}

func keyStorePath(t *testing.T, assets fixtureAssets) string {
	t.Helper()

	for _, path := range assets.P12 {
		if strings.Contains(filepath.Base(path), "___Valid_") {
			return path
		}
	}
	if len(assets.P12) == 0 {
		t.Skip("no PKCS#12 fixtures found")
	}

	return assets.P12[0]
}

func readFixtureExample(t *testing.T, assets fixtureAssets, name string) []byte {
	t.Helper()

	path := assets.Examples[name]
	if path == "" {
		t.Fatalf("fixture example %q not found", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture example %q: %v", name, err)
	}

	return data
}

func certificatePath(t *testing.T, assets fixtureAssets, name string) string {
	t.Helper()

	path := assets.Certs[name]
	if path == "" {
		t.Fatalf("fixture certificate %q not found", name)
	}

	return path
}

func certificateSource(data []byte) Source {
	if bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----")) {
		return PEM(data)
	}

	return DER(data)
}

func loadFixtureAssets(t *testing.T) fixtureAssets {
	t.Helper()
	return testfixture.LoadSDK(t, defaultAssetDir)
}

func requireContains(t *testing.T, name, value, substr string) {
	t.Helper()

	if !strings.Contains(value, substr) {
		t.Fatalf("%s = %q, want substring %q", name, value, substr)
	}
}

func requireKalkanError(t *testing.T, name string, err error) {
	t.Helper()

	if _, ok := errors.AsType[*ckalkan.KalkanError](err); !ok {
		t.Fatalf("%s returned non-Kalkan error: %T %v", name, err, err)
	}
}

func openFixtureSigningClient(t *testing.T) *Client {
	t.Helper()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)
	ctx := context.Background()
	if err := client.LoadKeyStore(ctx, KeyStore{Type: PKCS12, Path: keyStorePath(t, assets), Password: fixturePassword}); err != nil {
		t.Fatalf("LoadKeyStore: %v", err)
	}
	return client
}

func requireNativeErrorCode(t *testing.T, name string, err error, want ckalkan.ErrorCode) {
	t.Helper()

	// A setup, validation, or infrastructure error cannot stand in for the
	// expected cryptographic rejection, nor can an arbitrary native info string.
	code, ok := ckalkan.ErrorCodeOf(err)
	if !ok || code != want {
		t.Fatalf("%s error = %v, want KalkanCrypt code %s", name, err, want.Hex())
	}
}
