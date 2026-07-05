package ckalkan

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestUnsupportedBuildReturnsUnavailable(t *testing.T) {
	if kalkancrypt.Available() {
		t.Skip("test is for builds without a native KalkanCrypt loader")
	}

	if _, err := New(); !errors.Is(err, ErrNoLibrary) {
		t.Fatalf("New without library returned %v, want ErrNoLibrary", err)
	}

	if _, err := New(WithLibrary(filepath.Join(t.TempDir(), "missing.so"))); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("New with library on unsupported build returned %v, want ErrUnavailable", err)
	}

	var cli Client
	if err := cli.Init(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("method on unsupported build returned %v, want ErrUnavailable", err)
	}
}

func TestUnavailableErrorsArePlatformNeutral(t *testing.T) {
	for _, err := range []error{ErrUnavailable, kalkancrypt.ErrUnavailable} {
		if strings.Contains(strings.ToLower(err.Error()), "linux") {
			t.Fatalf("unavailable error hard-codes Linux: %q", err)
		}
	}
}
