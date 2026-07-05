package ckalkan_test

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

const (
	sdkTestPassword       = "Qwerty12"
	defaultSDKTestdataDir = "testdata"
)

type sdkTestAssets struct {
	Root     string
	P12      []string
	Certs    []string
	Examples map[string]string
	ZIPs     []string
}

func TestDefaultSDKAssetSearchUsesRepositoryTestdata(t *testing.T) {
	roots := defaultSDKAssetRoots()
	if len(roots) == 0 {
		t.Fatal("default SDK asset roots are empty")
	}
	for _, root := range roots {
		slashRoot := filepath.ToSlash(root)
		if slashRoot == "testdata" || slashRoot == "../testdata" {
			return
		}
	}
	t.Fatalf("default SDK asset roots %q do not include repository testdata", roots)
}

// TestSDKTestdataAssets documents the SDK fixture subset committed for real
// integration tests. It does not load the native library.
func TestSDKTestdataAssets(t *testing.T) {
	assets := repositorySDKTestAssets(t)
	if len(assets.P12) != 24 {
		t.Fatalf("SDK P12 fixture count = %d, want 24", len(assets.P12))
	}
	for _, name := range []string{"test_xml", "test_wsse", "test_CMS_GOST", "CMS_for_double_sign", "text"} {
		if assets.Examples[name] == "" {
			t.Fatalf("missing SDK example %q", name)
		}
	}
	if len(assets.ZIPs) < 5 {
		t.Fatalf("SDK ZIP fixture count = %d, want at least 5", len(assets.ZIPs))
	}
}

func realSDKBufferOptions() []ckalkan.Option {
	return []ckalkan.Option{
		ckalkan.WithBufferSize(1 << 20),
		ckalkan.WithListBufferSize(1 << 20),
		ckalkan.WithMaxBufferSize(32 << 20),
	}
}

func sdkAssetsForIntegration(t *testing.T) sdkTestAssets {
	t.Helper()
	assetSpec := strings.TrimSpace(os.Getenv("KALKANCRYPT_SDK_ASSETS"))
	if assetSpec != "" {
		roots := materializeAssetRoots(t, filepath.SplitList(assetSpec))
		assets := collectSDKTestAssets(t, roots)
		if len(assets.P12) == 0 {
			explainSkipNoAssets(t, assetSpec)
		}
		return assets
	}
	return repositorySDKTestAssets(t)
}

func repositorySDKTestAssets(t *testing.T) sdkTestAssets {
	t.Helper()
	for _, root := range defaultSDKAssetRoots() {
		info, err := os.Stat(root)
		if err == nil && info.IsDir() {
			return collectSDKTestAssets(t, []string{root})
		}
	}
	explainSkipNoAssets(t, strings.Join(defaultSDKAssetRoots(), string(os.PathListSeparator)))
	return sdkTestAssets{}
}

func defaultSDKAssetRoots() []string {
	return []string{
		filepath.FromSlash(defaultSDKTestdataDir),
		filepath.Join("..", filepath.FromSlash(defaultSDKTestdataDir)),
	}
}

func collectSDKTestAssets(t *testing.T, roots []string) sdkTestAssets {
	t.Helper()
	assets := sdkTestAssets{Examples: make(map[string]string)}
	if len(roots) == 1 {
		assets.Root = roots[0]
	}
	for _, root := range roots {
		if assets.Root == "" {
			assets.Root = root
		}
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				name := entry.Name()
				if name == "__MACOSX" || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasPrefix(entry.Name(), "._") {
				return nil
			}
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
				registerSDKExample(assets.Examples, base, path)
			case ".txt", ".xml":
				registerSDKExample(assets.Examples, base, path)
			case ".zip":
				if strings.HasPrefix(base, "zip_") || base == "sign" {
					assets.ZIPs = append(assets.ZIPs, path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan SDK assets in %s: %v", root, err)
		}
	}
	sort.Strings(assets.P12)
	sort.Strings(assets.Certs)
	sort.Strings(assets.ZIPs)
	return assets
}

func registerSDKExample(examples map[string]string, base, path string) {
	key := strings.TrimSpace(base)
	switch key {
	case "test_xml":
		examples["test_xml"] = path
	case "test_wsse", "wsse":
		examples["test_wsse"] = path
	case "test_CMS_GOST":
		examples["test_CMS_GOST"] = path
	case "CMS_for_double_sign":
		examples["CMS_for_double_sign"] = path
	case "test_CERT_GOST":
		examples["test_CERT_GOST"] = path
	case "text":
		examples["text"] = path
	}
}

func chooseSDKStore(t *testing.T, stores []string) string {
	t.Helper()
	if len(stores) == 0 {
		t.Fatal("no SDK PKCS#12 stores found")
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

func loadSDKCertificates(t *testing.T, client *ckalkan.Client, assets sdkTestAssets) {
	t.Helper()
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
			t.Logf("X509LoadCertificateFromFile(%s) returned %v", certPath, err)
		}
		format := ckalkan.CertDER
		if bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----")) {
			format = ckalkan.CertPEM
		}
		if err := client.X509LoadCertificateFromBuffer(data, format); err != nil {
			t.Logf("X509LoadCertificateFromBuffer(%s) returned %v", certPath, err)
		}
	}
}

func readSDKExample(t *testing.T, assets sdkTestAssets, name string) []byte {
	t.Helper()
	path := assets.Examples[name]
	if path == "" {
		t.Fatalf("SDK example %q not found", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SDK example %s: %v", path, err)
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
			roots = append(roots, extractZipForTest(t, path))
			continue
		}
		roots = append(roots, filepath.Dir(path))
	}
	return roots
}

func extractZipForTest(t *testing.T, zipPath string) string {
	t.Helper()
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip %s: %v", zipPath, err)
	}
	defer reader.Close()

	root := t.TempDir()
	for _, file := range reader.File {
		name := filepath.Clean(file.Name)
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) || strings.Contains(name, string(filepath.Separator)+".."+string(filepath.Separator)) {
			t.Fatalf("unsafe path %q in %s", file.Name, zipPath)
		}
		if file.FileInfo().IsDir() {
			continue
		}
		outPath := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", outPath, err)
		}
		in, err := file.Open()
		if err != nil {
			t.Fatalf("open %s inside %s: %v", file.Name, zipPath, err)
		}
		out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			in.Close()
			t.Fatalf("create %s: %v", outPath, err)
		}
		_, copyErr := io.Copy(out, in)
		closeInErr := in.Close()
		closeOutErr := out.Close()
		if copyErr != nil || closeInErr != nil || closeOutErr != nil {
			t.Fatalf("extract %s: copy=%v closeIn=%v closeOut=%v", file.Name, copyErr, closeInErr, closeOutErr)
		}
	}
	return root
}
