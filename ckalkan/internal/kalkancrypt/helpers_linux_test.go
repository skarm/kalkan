//go:build linux && cgo

package kalkancrypt_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

const (
	kcstPKCS12 = 0x00000001
	certDER    = 0x00000101
	certPEM    = 0x00000102
	certCA     = 0x00000201
	certInter  = 0x00000202
	certUser   = 0x00000204
	useNothing = 0x00000401
	useOCSP    = 0x00000404

	signDraft       = 0x00000001
	signCMS         = 0x00000002
	inPEM           = 0x00000004
	inBase64        = 0x00000010
	detachedData    = 0x00000040
	outPEM          = 0x00000200
	outBase64       = 0x00000800
	inFile          = 0x00008000
	proxyOff        = 0x00001000
	noCheckCertTime = 0x00010000
	xmlInclC14N     = 0x01000001

	certPropSubjectCommonName = 0x0000080a
	certPropSignatureAlg      = 0x0000081c

	kcrOK = 0
)

type sdkAssets struct {
	root     string
	p12      []string
	certs    []string
	examples map[string]string
	zips     []string
}

func openContext(t *testing.T) *kalkancrypt.Context {
	t.Helper()

	if !kalkancrypt.Available() {
		t.Fatal("Available returned false on linux+cgo")
	}
	library := strings.TrimSpace(os.Getenv("KALKANCRYPT_LIBRARY"))
	if library == "" {
		t.Skip("set KALKANCRYPT_LIBRARY to run KalkanCrypt tests")
	}

	ctx, err := kalkancrypt.Open(library)
	if err != nil {
		t.Fatalf("Open(%q) failed: %v", library, err)
	}
	t.Cleanup(func() {
		ctx.XMLFinalize()
		ctx.Finalize()
		if err := ctx.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	})

	if code := ctx.Init(); code != kcrOK {
		t.Fatalf("Init = %#x, want %#x", code, kcrOK)
	}

	return ctx
}

func loadPKCS12Fixture(t *testing.T, ctx *kalkancrypt.Context) string {
	t.Helper()

	p12 := firstPKCS12Fixture(t)
	if code := ctx.LoadKeyStore(kcstPKCS12, "Qwerty12", p12, ""); code != kcrOK {
		t.Fatalf("LoadKeyStore(%s) = %#x, want %#x", filepath.Base(p12), code, kcrOK)
	}

	return p12
}

func requireBufferOK(t *testing.T, name string, result kalkancrypt.BufferResult, err error) []byte {
	t.Helper()

	if err != nil {
		t.Fatalf("%s returned Go error: %v", name, err)
	}
	if result.Code != kcrOK {
		t.Fatalf("%s code = %#x, want %#x", name, result.Code, kcrOK)
	}
	if result.OutLen != len(result.Data) {
		t.Fatalf("%s OutLen = %d, data length = %d", name, result.OutLen, len(result.Data))
	}
	if len(result.Data) == 0 {
		t.Fatalf("%s returned empty data", name)
	}

	return result.Data
}

func requireVerifyOK(t *testing.T, name string, result kalkancrypt.VerifyResult, err error) kalkancrypt.VerifyResult {
	t.Helper()

	if err != nil {
		t.Fatalf("%s returned Go error: %v", name, err)
	}
	if result.Code != kcrOK {
		t.Fatalf("%s code = %#x, want %#x; info=%q", name, result.Code, kcrOK, result.Info)
	}

	return result
}

func requireNativeFailureCode(t *testing.T, name string, code uint64) {
	t.Helper()

	if code == kcrOK {
		t.Fatalf("%s unexpectedly returned KCR_OK", name)
	}
}

func requireBufferNativeFailure(t *testing.T, name string, result kalkancrypt.BufferResult, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("%s returned Go error: %v", name, err)
	}
	requireNativeFailureCode(t, name, result.Code)
}

func requireVerifyNativeFailure(t *testing.T, name string, result kalkancrypt.VerifyResult, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("%s returned Go error: %v", name, err)
	}
	requireNativeFailureCode(t, name, result.Code)
}

func firstPKCS12Fixture(t *testing.T) string {
	t.Helper()

	assets := sdkAssetsForIntegration(t)
	if len(assets.p12) == 0 {
		t.Skip("no PKCS#12 fixtures found in SDK test assets")
	}

	return assets.p12[0]
}

func sdkAssetsForIntegration(t *testing.T) sdkAssets {
	t.Helper()

	var roots []string
	if assetSpec := strings.TrimSpace(os.Getenv("KALKANCRYPT_SDK_ASSETS")); assetSpec != "" {
		for _, path := range filepath.SplitList(assetSpec) {
			path = strings.TrimSpace(path)
			if path != "" {
				roots = append(roots, path)
			}
		}
	}
	if len(roots) == 0 {
		wd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, filepath.Join(wd, "..", "..", "..", "testdata"))
	}

	assets := sdkAssets{examples: make(map[string]string)}
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		if assets.root == "" {
			assets.root = root
		}
		err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "__MACOSX" {
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
				assets.p12 = append(assets.p12, path)
			case ".cer", ".crt", ".pem", ".der":
				assets.certs = append(assets.certs, path)
				registerSDKExample(assets.examples, base, path)
			case ".txt", ".xml":
				registerSDKExample(assets.examples, base, path)
			case ".zip":
				if strings.HasPrefix(base, "zip_") || base == "sign" {
					assets.zips = append(assets.zips, path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan SDK assets in %s: %v", root, err)
		}
	}
	sort.Strings(assets.p12)
	sort.Strings(assets.certs)
	sort.Strings(assets.zips)
	if assets.root == "" {
		t.Skip("no usable KalkanCrypt SDK assets found")
	}

	return assets
}

func registerSDKExample(examples map[string]string, base, path string) {
	switch strings.TrimSpace(base) {
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

func readSDKExample(t *testing.T, assets sdkAssets, name string) []byte {
	t.Helper()

	path := assets.examples[name]
	if path == "" {
		t.Fatalf("SDK example %q not found", name)
	}

	return readFile(t, path)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return data
}

func loadSDKCertificates(t *testing.T, ctx *kalkancrypt.Context, assets sdkAssets) {
	t.Helper()

	if len(assets.certs) == 0 {
		t.Skip("no SDK certificate fixtures found")
	}

	var loaded int
	for _, certPath := range assets.certs {
		certType := certUser
		lower := strings.ToLower(filepath.Base(certPath))
		switch {
		case strings.Contains(lower, "root"):
			certType = certCA
		case strings.Contains(lower, "nca"):
			certType = certInter
		}
		if code := ctx.X509LoadCertificateFromFile(certPath, certType); code == kcrOK {
			loaded++
		} else {
			t.Logf("X509LoadCertificateFromFile(%s) = %#x", certPath, code)
		}
	}
	if loaded == 0 {
		t.Fatal("no SDK certificates could be loaded")
	}
}

func firstSDKZip(t *testing.T, assets sdkAssets) string {
	t.Helper()

	if len(assets.zips) == 0 {
		t.Skip("no SDK ZIP fixtures found")
	}

	return assets.zips[0]
}

func firstExistingFile(paths ...string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}
