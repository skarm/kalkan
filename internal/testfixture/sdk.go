package testfixture

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// SDKAssets indexes the public certificate, key-store, and document fixtures in an SDK.
type SDKAssets struct {
	P12      []string
	ZIPs     []string
	Examples map[string]string
	Certs    map[string]string
}

// LoadSDK discovers SDK assets from KALKANCRYPT_SDK_ASSETS or defaultDir.
// Relative configured paths resolve beside defaultDir, so every test package
// uses the same repository-relative fixtures. Archive roots are extracted into
// test-owned temporary directories.
func LoadSDK(t testing.TB, defaultDir string) SDKAssets {
	t.Helper()

	roots := sdkAssetRoots(t, defaultDir)

	assets := collectSDKAssets(t, roots)
	if len(assets.P12) == 0 {
		t.Skip("no usable KalkanCrypt fixture assets found in " + strings.Join(roots, string(os.PathListSeparator)))
	}

	return assets
}

func sdkAssetRoots(t testing.TB, defaultDir string) []string {
	t.Helper()

	assetSpec := strings.TrimSpace(os.Getenv("KALKANCRYPT_SDK_ASSETS"))

	configured := assetSpec != ""
	if !configured {
		assetSpec = filepath.FromSlash(defaultDir)
	}

	var roots []string

	for _, raw := range filepath.SplitList(assetSpec) {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}

		if configured && !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(defaultDir), path)
		}

		info, err := os.Stat(path) //nolint:gosec // Fixture roots are explicitly selected by the test runner and may be outside the repository.
		if err != nil {
			continue
		}

		if info.IsDir() {
			roots = append(roots, path)
			continue
		}

		if strings.EqualFold(filepath.Ext(path), ".zip") {
			roots = append(roots, ExtractZIP(t, path, RejectDuplicates))
			continue
		}

		roots = append(roots, filepath.Dir(path))
	}

	if len(roots) == 0 {
		t.Skip("no usable KalkanCrypt fixture assets found in " + assetSpec)
	}

	return roots
}

func collectSDKAssets(t testing.TB, roots []string) SDKAssets {
	t.Helper()

	assets := SDKAssets{Examples: make(map[string]string), Certs: make(map[string]string)}

	WalkFiles(t, roots, func(path string) {
		ext := strings.ToLower(filepath.Ext(path))
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

		switch ext {
		case ".p12", ".pfx":
			assets.P12 = append(assets.P12, path)
		case ".txt", ".xml", ".pem", ".cer", ".crt", ".der":
			RegisterExample(assets.Examples, base, path)
			registerSDKCertificate(assets.Certs, base, path)
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

func registerSDKCertificate(certs map[string]string, base, path string) {
	lowerBase := strings.ToLower(strings.TrimSpace(base))
	switch lowerBase {
	case "root_test_gost_2022", "nca_gost2022_test":
		if certs[lowerBase] == "" || strings.EqualFold(filepath.Ext(path), ".pem") {
			certs[lowerBase] = path
		}
	}
}
