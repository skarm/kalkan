package kalkan

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/internal/testfixture"
)

const (
	fixturePassword  = "Qwerty12"
	defaultAssetDir  = "testdata"
	assetEnvironment = "KALKANCRYPT_SDK_ASSETS"
	testTSAURL       = "http://test.pki.gov.kz/tsp/"
	testOCSPURL      = "http://test.pki.gov.kz/ocsp/"
)

type fixtureAssets struct {
	P12      []string
	ZIPs     []string
	Examples map[string]string
	Certs    map[string]string
}

func openFixtureClient(t *testing.T, assets fixtureAssets) *Client {
	t.Helper()

	library := strings.TrimSpace(os.Getenv("KALKANCRYPT_LIBRARY"))
	if library == "" {
		t.Skip("set KALKANCRYPT_LIBRARY to run native-backed root API tests")
	}

	client, err := Open(context.Background(),
		WithLibraryPath(library),
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

	roots := assetRoots(t)
	assets := collectFixtureAssets(t, roots)
	if len(assets.P12) == 0 {
		t.Skip("no usable KalkanCrypt fixture assets found in " + strings.Join(roots, string(os.PathListSeparator)))
	}

	return assets
}

func assetRoots(t *testing.T) []string {
	t.Helper()

	assetSpec := strings.TrimSpace(os.Getenv(assetEnvironment))
	if assetSpec == "" {
		assetSpec = filepath.FromSlash(defaultAssetDir)
	}

	var roots []string
	for _, raw := range filepath.SplitList(assetSpec) {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.IsDir() {
			roots = append(roots, path)
			continue
		}

		if strings.EqualFold(filepath.Ext(path), ".zip") {
			roots = append(roots, testfixture.ExtractZIP(t, path, testfixture.RejectDuplicates))
			continue
		}

		roots = append(roots, filepath.Dir(path))
	}
	if len(roots) == 0 {
		t.Skip("no usable KalkanCrypt fixture assets found in " + assetSpec)
	}

	return roots
}

func collectFixtureAssets(t *testing.T, roots []string) fixtureAssets {
	t.Helper()

	assets := fixtureAssets{Examples: make(map[string]string), Certs: make(map[string]string)}
	testfixture.WalkFiles(t, roots, func(path string) {
		ext := strings.ToLower(filepath.Ext(path))
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		switch ext {
		case ".p12", ".pfx":
			assets.P12 = append(assets.P12, path)
		case ".txt", ".xml", ".pem", ".cer", ".crt", ".der":
			testfixture.RegisterExample(assets.Examples, base, path)
			registerCertificate(assets.Certs, base, path)
		case ".zip":
			if strings.HasPrefix(base, "zip_") || base == "sign" {
				assets.ZIPs = append(assets.ZIPs, path)
			}
		}
	})
	sort.Strings(assets.P12)
	sort.Strings(assets.ZIPs)

	return assets
}

func registerCertificate(certs map[string]string, base, path string) {
	lowerBase := strings.ToLower(strings.TrimSpace(base))
	switch lowerBase {
	case "root_test_gost_2022", "nca_gost2022_test":
		if certs[lowerBase] == "" || strings.EqualFold(filepath.Ext(path), ".pem") {
			certs[lowerBase] = path
		}
	}
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
