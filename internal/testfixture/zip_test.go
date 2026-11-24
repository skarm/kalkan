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

func TestExtractZIPRejectsSymlinkEscapes(t *testing.T) {
	for _, parentLink := range []bool{false, true} {
		name := "file link"
		if parentLink {
			name = "directory link"
		}
		t.Run(name, func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			destination := filepath.Join(outside, "fixture.xml")
			if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			entry, target := "fixture.xml", destination
			link := filepath.Join(root, entry)
			if parentLink {
				entry, target = "linked/fixture.xml", outside
				link = filepath.Join(root, "linked")
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlinks are unavailable: %v", err)
			}
			archive := writeArchive(t, []archiveEntry{{entry, "overwritten"}})
			if err := extractZIP(archive, root, OverwriteDuplicates); err == nil {
				t.Fatal("extraction followed a symlink outside the root")
			}
			data, err := os.ReadFile(destination)
			if err != nil || string(data) != "original" {
				t.Fatalf("extraction changed a file outside the root: %q, %v", data, err)
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
