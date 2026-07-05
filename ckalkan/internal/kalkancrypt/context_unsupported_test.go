//go:build !(linux && cgo) && !windows

package kalkancrypt_test

import (
	"errors"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestUnsupportedBuildReportsUnavailable(t *testing.T) {
	if kalkancrypt.Available() {
		t.Fatal("Available returned true on a build without a native driver")
	}

	ctx, err := kalkancrypt.Open("libkalkancrypt.so")
	if !errors.Is(err, kalkancrypt.ErrUnavailable) {
		t.Fatalf("Open returned error %v, want ErrUnavailable", err)
	}
	if ctx != nil {
		t.Fatalf("Open returned context %#v on unsupported build", ctx)
	}
}
