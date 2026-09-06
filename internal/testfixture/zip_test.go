package testfixture

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractZIPPreservesBinaryContents(t *testing.T) {
	archive := writeArchive(t, []archiveEntry{{"nested/", ""}, {"nested/fixture.der", "\x00\xff\x01"}})
	root := ExtractZIP(t, archive, RejectDuplicates)
	got, err := os.ReadFile(filepath.Join(root, "nested", "fixture.der"))
	if err != nil || !bytes.Equal(got, []byte{0, 255, 1}) {
		t.Fatalf("extracted bytes = %v, error = %v", got, err)
	}
}

func TestExtractZIPRetainsDuplicateEntryPolicy(t *testing.T) {
	archive := writeArchive(t, []archiveEntry{{"same.xml", "first"}, {"same.xml", "last"}})
	for _, tc := range []struct {
		name       string
		duplicates DuplicatePolicy
		want       string
		wantErr    error
	}{
		{"reject duplicates", RejectDuplicates, "first", os.ErrExist},
		{"last entry wins", OverwriteDuplicates, "last", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := extractZIP(archive, root, tc.duplicates); !errors.Is(err, tc.wantErr) {
				t.Fatalf("extract error = %v, want %v", err, tc.wantErr)
			}
			got, err := os.ReadFile(filepath.Join(root, "same.xml"))
			if err != nil || string(got) != tc.want {
				t.Fatalf("extracted contents = %q, error = %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestExtractZIPRejectsPathsOutsideRoot(t *testing.T) {
	absolutePath := filepath.ToSlash(filepath.Join(t.TempDir(), "escape"))
	for _, name := range []string{"../escape", "nested/../../escape", absolutePath} {
		t.Run(name, func(t *testing.T) {
			archive := writeArchive(t, []archiveEntry{{name, "unsafe"}})
			root := filepath.Join(t.TempDir(), "output")
			if err := extractZIP(archive, root, RejectDuplicates); err == nil || !strings.Contains(err.Error(), "unsafe path") {
				t.Fatalf("extract error = %v, want unsafe path rejection", err)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("archive wrote outside root: %v", err)
			}
		})
	}
}

type archiveEntry struct{ name, content string }

func writeArchive(t *testing.T, entries []archiveEntry) string {
	t.Helper()
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for _, entry := range entries {
		out, err := writer.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := out.Write([]byte(entry.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixtures.zip")
	if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractZIPRejectsUnknownDuplicatePolicy(t *testing.T) {
	archive := writeArchive(t, []archiveEntry{{"fixture.xml", "content"}})
	root := t.TempDir()
	if err := extractZIP(archive, root, DuplicatePolicy(99)); err == nil || !strings.Contains(err.Error(), "unknown ZIP duplicate policy") {
		t.Fatalf("extract error = %v, want unknown duplicate policy rejection", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid policy wrote files: entries=%v, error=%v", entries, err)
	}
}
