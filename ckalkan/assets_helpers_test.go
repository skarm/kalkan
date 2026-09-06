package ckalkan_test

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/internal/testfixture"
)

const (
	fixturePassword    = "Qwerty12"
	defaultTestdataDir = "testdata"
)

type fixtureAssets struct {
	Root     string
	P12      []string
	Certs    []string
	Examples map[string]string
	ZIPs     []string
}

func TestDefaultAssetSearchUsesRepositoryTestdata(t *testing.T) {
	roots := defaultAssetRoots()
	if len(roots) == 0 {
		t.Fatal("default asset roots are empty")
	}
	for _, root := range roots {
		slashRoot := filepath.ToSlash(root)
		if slashRoot == "testdata" || slashRoot == "../testdata" {
			return
		}
	}
	t.Fatalf("default asset roots %q do not include repository testdata", roots)
}

// TestRepositoryFixtureAssets documents the fixture subset committed for real
// native-backed tests. It does not load the native library.
func TestRepositoryFixtureAssets(t *testing.T) {
	assets := repositoryFixtureAssets(t)
	if len(assets.P12) != 24 {
		t.Fatalf("PKCS#12 fixture count = %d, want 24", len(assets.P12))
	}
	for _, name := range []string{"test_xml", "test_wsse", "test_CMS_GOST", "CMS_for_double_sign", "text"} {
		if assets.Examples[name] == "" {
			t.Fatalf("missing fixture example %q", name)
		}
	}
	if len(assets.ZIPs) < 5 {
		t.Fatalf("ZIP fixture fixture count = %d, want at least 5", len(assets.ZIPs))
	}
}

func largeBufferOptions() []ckalkan.Option {
	return []ckalkan.Option{
		ckalkan.WithBufferSize(1 << 20),
		ckalkan.WithListBufferSize(1 << 20),
		ckalkan.WithMaxBufferSize(32 << 20),
	}
}

func loadFixtureAssets(t *testing.T) fixtureAssets {
	t.Helper()
	assetSpec := strings.TrimSpace(os.Getenv("KALKANCRYPT_SDK_ASSETS"))
	if assetSpec != "" {
		roots := materializeAssetRoots(t, filepath.SplitList(assetSpec))
		assets := collectFixtureAssets(t, roots)
		if len(assets.P12) == 0 {
			explainSkipNoAssets(t, assetSpec)
		}
		return assets
	}
	return repositoryFixtureAssets(t)
}

func repositoryFixtureAssets(t *testing.T) fixtureAssets {
	t.Helper()
	for _, root := range defaultAssetRoots() {
		info, err := os.Stat(root)
		if err == nil && info.IsDir() {
			return collectFixtureAssets(t, []string{root})
		}
	}
	explainSkipNoAssets(t, strings.Join(defaultAssetRoots(), string(os.PathListSeparator)))
	return fixtureAssets{}
}

func defaultAssetRoots() []string {
	return []string{
		filepath.FromSlash(defaultTestdataDir),
		filepath.Join("..", filepath.FromSlash(defaultTestdataDir)),
	}
}

func collectFixtureAssets(t *testing.T, roots []string) fixtureAssets {
	t.Helper()

	assets := fixtureAssets{Examples: make(map[string]string)}
	if len(roots) > 0 {
		assets.Root = roots[0]
	}
	testfixture.WalkFiles(t, roots, func(path string) {
		ext := strings.ToLower(filepath.Ext(path))
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		switch ext {
		case ".p12", ".pfx":
			assets.P12 = append(assets.P12, path)
		case ".cer", ".crt", ".pem", ".der":
			lowerPath := strings.ToLower(filepath.ToSlash(path))
			lowerBase := strings.ToLower(base)
			if strings.Contains(lowerPath, "/cert") ||
				strings.Contains(lowerPath, "keys and certs") ||
				strings.Contains(lowerBase, "cert") ||
				strings.Contains(lowerBase, "root_") ||
				strings.Contains(lowerBase, "nca_") {
				assets.Certs = append(assets.Certs, path)
			}
			testfixture.RegisterExample(assets.Examples, base, path)
		case ".txt", ".xml":
			testfixture.RegisterExample(assets.Examples, base, path)
		case ".zip":
			if strings.HasPrefix(base, "zip_") || base == "sign" {
				assets.ZIPs = append(assets.ZIPs, path)
			}
		}
	})
	sort.Strings(assets.P12)
	sort.Strings(assets.Certs)
	sort.Strings(assets.ZIPs)

	return assets
}

func chooseStore(t *testing.T, stores []string) string {
	t.Helper()
	if len(stores) == 0 {
		t.Fatal("no PKCS#12 stores found")
	}
	for _, store := range stores {
		lower := strings.ToLower(filepath.ToSlash(store))
		if (strings.Contains(lower, "/valid/") || strings.Contains(lower, "_valid_")) &&
			!strings.Contains(lower, "/revoked/") &&
			!strings.Contains(lower, "_revoked_") {
			return store
		}
	}
	return stores[0]
}

func loadCertificates(t *testing.T, client *ckalkan.Client, assets fixtureAssets) {
	t.Helper()
	if len(assets.Certs) == 0 {
		t.Fatal("certificate fixtures are required for native test setup")
	}
	// The selected certificates form the test's trust setup. A rejected input
	// is a setup failure; negative certificate fixtures belong in explicit tests.
	for _, certPath := range assets.Certs {
		data, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("read certificate %s: %v", certPath, err)
		}
		certType := ckalkan.CertUser
		lower := strings.ToLower(filepath.Base(certPath))
		if strings.Contains(lower, "root") {
			certType = ckalkan.CertCA
		} else if strings.Contains(lower, "nca") {
			certType = ckalkan.CertIntermediate
		}
		if strings.EqualFold(filepath.Ext(certPath), ".crl") {
			continue
		}
		if err := client.X509LoadCertificateFromFile(certPath, certType); err != nil {
			t.Fatalf("load certificate fixture from file %s: %v", certPath, err)
		}
		format := ckalkan.CertDER
		if bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----")) {
			format = ckalkan.CertPEM
		}
		if err := client.X509LoadCertificateFromBuffer(data, format); err != nil {
			t.Fatalf("load certificate fixture from buffer %s: %v", certPath, err)
		}
	}
}

func readExample(t *testing.T, assets fixtureAssets, name string) []byte {
	t.Helper()
	path := assets.Examples[name]
	if path == "" {
		t.Fatalf("fixture example %q not found", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture example %s: %v", path, err)
	}
	return data
}

func materializeAssetRoots(t *testing.T, paths []string) []string {
	t.Helper()
	var roots []string
	for _, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.IsDir() {
			roots = append(roots, path)
			continue
		}
		if strings.EqualFold(filepath.Ext(path), ".zip") {
			roots = append(roots, testfixture.ExtractZIP(t, path, testfixture.OverwriteDuplicates))
			continue
		}
		roots = append(roots, filepath.Dir(path))
	}
	return roots
}
