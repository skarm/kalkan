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

func TestLoadSDKUsesSameRootAcrossTestPackages(t *testing.T) {
	repository := t.TempDir()
	fixtures := filepath.Join(repository, "testdata")
	if err := os.Mkdir(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	keyStore := filepath.Join(fixtures, "identity.p12")
	if err := os.WriteFile(keyStore, []byte("public fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A nested integration package must not silently skip SDK tests because
	// go test executes it with a different package working directory.
	t.Chdir(t.TempDir())
	for _, configured := range []string{"", "./testdata", fixtures} {
		t.Run(configured, func(t *testing.T) {
			t.Setenv("KALKANCRYPT_SDK_ASSETS", configured)
			assets := testfixture.LoadSDK(t, fixtures)
			if !reflect.DeepEqual(assets.P12, []string{keyStore}) {
				t.Fatalf("discovered key stores = %q, want %q", assets.P12, keyStore)
			}
		})
	}
}
