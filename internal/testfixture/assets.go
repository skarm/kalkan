// Package testfixture shares fixture discovery and file handling across test
// layers. Filesystem helpers report failures through testing.TB; ZIP copies
// and extracted archives belong to the calling test and are cleaned up with it.
// Client setup and certificate selection remain local to each layer.
package testfixture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WalkFiles visits fixture files in root and lexical path order, skipping
// repository metadata and macOS resource forks.
func WalkFiles(t testing.TB, roots []string, visit func(path string)) {
	t.Helper()

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if entry.IsDir() {
				if entry.Name() == "__MACOSX" || entry.Name() == ".git" {
					return filepath.SkipDir
				}

				return nil
			}

			if !strings.HasPrefix(entry.Name(), "._") {
				visit(path)
			}

			return nil
		})
		if err != nil {
			t.Fatalf("scan fixture assets in %s: %v", root, err)
		}
	}
}

// RegisterExample records known SDK example names, including the WSSE alias.
func RegisterExample(examples map[string]string, base, path string) {
	switch strings.TrimSpace(base) {
	case "CMS_for_double_sign":
		examples["CMS_for_double_sign"] = path
	case "test_CERT_GOST":
		examples["test_CERT_GOST"] = path
	case "test_CMS_GOST":
		examples["test_CMS_GOST"] = path
	case "text":
		examples["text"] = path
	case "test_xml":
		examples["test_xml"] = path
	case "test_wsse", "wsse":
		examples["test_wsse"] = path
	}
}

// CopyZIP gives a test its own copy of a mutable ZIP fixture.
func CopyZIP(t testing.TB, srcPath string) string {
	t.Helper()

	content, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read source ZIP fixture %s: %v", srcPath, err)
	}

	dstPath := filepath.Join(t.TempDir(), filepath.Base(srcPath))
	if err := os.WriteFile(dstPath, content, 0o644); err != nil { //nolint:gosec // Public test fixtures retain their existing permissions in a private temporary directory.
		t.Fatalf("write isolated ZIP fixture %s: %v", dstPath, err)
	}

	return dstPath
}
