package testfixture_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/skarm/kalkan/internal/testfixture"
)

func TestWalkFilesSkipsMetadataAndPreservesRootOrder(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	for _, name := range []string{"b.p12", "nested/a.xml", ".git/hidden.p12", "__MACOSX/hidden.xml", "nested/._a.xml"} {
		path := filepath.Join(first, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	last := filepath.Join(second, "a.p12")
	if err := os.WriteFile(last, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	var got []string
	testfixture.WalkFiles(t, []string{first, second}, func(path string) { got = append(got, path) })
	want := []string{filepath.Join(first, "b.p12"), filepath.Join(first, "nested", "a.xml"), last}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("files = %q, want %q", got, want)
	}
}
