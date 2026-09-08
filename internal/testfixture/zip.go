package testfixture

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// DuplicatePolicy controls entries that resolve to the same extracted path.
type DuplicatePolicy int

const (
	// RejectDuplicates fails when an archive repeats a file path.
	RejectDuplicates DuplicatePolicy = iota
	// OverwriteDuplicates keeps the last entry for each file path.
	OverwriteDuplicates
)

// ExtractZIP unpacks an SDK fixture archive into a fresh test-owned directory.
// It fails the test on extraction errors; the directory is removed at cleanup.
func ExtractZIP(t testing.TB, zipPath string, duplicates DuplicatePolicy) string {
	t.Helper()

	root := t.TempDir()
	if err := extractZIP(zipPath, root, duplicates); err != nil {
		t.Fatal(err)
	}

	return root
}

func extractZIP(zipPath, root string, duplicates DuplicatePolicy) error {
	flags := os.O_WRONLY | os.O_CREATE

	switch duplicates {
	case RejectDuplicates:
		flags |= os.O_EXCL
	case OverwriteDuplicates:
		flags |= os.O_TRUNC
	default:
		return fmt.Errorf("unknown ZIP duplicate policy %d", duplicates)
	}

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip %s: %w", zipPath, err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		name := filepath.Clean(file.Name)
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) ||
			strings.Contains(name, string(filepath.Separator)+".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe path %q in %s", file.Name, zipPath)
		}

		if file.FileInfo().IsDir() {
			continue
		}

		if err := extractZIPFile(file, filepath.Join(root, name), flags); err != nil {
			return fmt.Errorf("extract %s from %s: %w", file.Name, zipPath, err)
		}
	}

	return nil
}

func extractZIPFile(file *zip.File, outPath string, flags int) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}

	in, err := file.Open()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(outPath, flags, file.Mode()) //nolint:gosec // extractZIP rejects traversal and absolute names before joining the test-owned root.
	if err != nil {
		return errors.Join(err, in.Close())
	}

	_, copyErr := io.Copy(out, in) //nolint:gosec // SDK fixture archives are trusted test inputs.
	closeOutErr := out.Close()
	closeInErr := in.Close()

	return errors.Join(copyErr, closeOutErr, closeInErr)
}
