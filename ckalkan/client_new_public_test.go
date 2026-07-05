package ckalkan_test

import (
	"path/filepath"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestNewReturnsErrorForMissingLibrary(t *testing.T) {
	_, err := ckalkan.New(ckalkan.WithLibrary(filepath.Join(t.TempDir(), "missing.so")))
	if err == nil {
		t.Fatal("expected New to fail for a missing library")
	}
}
