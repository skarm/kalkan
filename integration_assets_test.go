package kalkan

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

const (
	sdkPassword         = "Qwerty12"
	defaultSDKAssetDir  = "testdata"
	sdkAssetEnvironment = "KALKANCRYPT_SDK_ASSETS"
)

type sdkAssets struct {
	P12      []string
	ZIPs     []string
	Examples map[string]string
	Certs    map[string]string
}

func openSDKClient(t *testing.T, assets sdkAssets) *Client {
	t.Helper()

	library := strings.TrimSpace(os.Getenv("KALKANCRYPT_LIBRARY"))
	if library == "" {
		t.Skip("set KALKANCRYPT_LIBRARY to run real root API integration tests")
	}

	client, err := Open(context.Background(),
		WithLibraryPath(library),
		WithEnvironment(TestEnvironment),
		WithTrustedCertificate(TrustedCertificate{
			Path: sdkCertificatePath(t, assets, "root_test_gost_2022"),
			Type: CertificateCA,
		}),
		WithTrustedCertificate(TrustedCertificate{
			Path: sdkCertificatePath(t, assets, "nca_gost2022_test"),
			Type: CertificateIntermediate,
		}),
	)
	if errors.Is(err, ckalkan.ErrUnavailable) {
		t.Skip("real root API integration tests require Linux with cgo enabled")
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

func sdkKeyStorePath(t *testing.T, assets sdkAssets) string {
	t.Helper()

	for _, path := range assets.P12 {
		if strings.Contains(filepath.Base(path), "___Valid_") {
			return path
		}
	}
	if len(assets.P12) == 0 {
		t.Skip("no SDK PKCS#12 fixtures found")
	}

	return assets.P12[0]
}

func readSDKExample(t *testing.T, assets sdkAssets, name string) []byte {
	t.Helper()

	path := assets.Examples[name]
	if path == "" {
		t.Fatalf("SDK example %q not found", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SDK example %q: %v", name, err)
	}

	return data
}

func sdkCertificatePath(t *testing.T, assets sdkAssets, name string) string {
	t.Helper()

	path := assets.Certs[name]
	if path == "" {
		t.Fatalf("SDK certificate %q not found", name)
	}

	return path
}

func sdkCertificateSource(data []byte) Source {
	if bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----")) {
		return PEM(data)
	}

	return DER(data)
}

func loadSDKAssets(t *testing.T) sdkAssets {
	t.Helper()

	roots := sdkAssetRoots(t)
	assets := collectSDKAssets(t, roots)
	if len(assets.P12) == 0 {
		t.Skip("no usable KalkanCrypt SDK assets found in " + strings.Join(roots, string(os.PathListSeparator)))
	}

	return assets
}

func sdkAssetRoots(t *testing.T) []string {
	t.Helper()

	assetSpec := strings.TrimSpace(os.Getenv(sdkAssetEnvironment))
	if assetSpec == "" {
		assetSpec = filepath.FromSlash(defaultSDKAssetDir)
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
			roots = append(roots, extractSDKZip(t, path))
			continue
		}

		roots = append(roots, filepath.Dir(path))
	}
	if len(roots) == 0 {
		t.Skip("no usable KalkanCrypt SDK assets found in " + assetSpec)
	}

	return roots
}

func collectSDKAssets(t *testing.T, roots []string) sdkAssets {
	t.Helper()

	assets := sdkAssets{Examples: make(map[string]string), Certs: make(map[string]string)}
	for _, root := range roots {
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
			case ".txt", ".xml", ".pem", ".cer", ".crt", ".der":
				registerSDKExample(assets.Examples, base, path)
				registerSDKCertificate(assets.Certs, base, path)
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
	sort.Strings(assets.ZIPs)

	return assets
}

func registerSDKExample(examples map[string]string, base, path string) {
	switch strings.TrimSpace(base) {
	case "test_CERT_GOST":
		examples["test_CERT_GOST"] = path
	case "test_xml":
		examples["test_xml"] = path
	case "test_wsse", "wsse":
		examples["test_wsse"] = path
	}
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

func extractSDKZip(t *testing.T, zipPath string) string {
	t.Helper()

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip %s: %v", zipPath, err)
	}
	defer reader.Close()

	root := t.TempDir()
	for _, file := range reader.File {
		name := filepath.Clean(file.Name)
		if strings.HasPrefix(name, "..") ||
			filepath.IsAbs(name) ||
			strings.Contains(name, string(filepath.Separator)+".."+string(filepath.Separator)) {
			t.Fatalf("unsafe path %q in %s", file.Name, zipPath)
		}
		if file.FileInfo().IsDir() {
			continue
		}

		outPath := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			t.Fatalf("create directory for %s: %v", outPath, err)
		}

		in, err := file.Open()
		if err != nil {
			t.Fatalf("open %s in %s: %v", file.Name, zipPath, err)
		}
		out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, file.Mode())
		if err != nil {
			_ = in.Close()
			t.Fatalf("create %s: %v", outPath, err)
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			_ = in.Close()
			t.Fatalf("extract %s: %v", file.Name, err)
		}
		if err := out.Close(); err != nil {
			_ = in.Close()
			t.Fatalf("close %s: %v", outPath, err)
		}
		if err := in.Close(); err != nil {
			t.Fatalf("close %s from %s: %v", file.Name, zipPath, err)
		}
	}

	return root
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
