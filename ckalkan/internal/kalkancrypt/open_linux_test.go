//go:build linux && cgo

package kalkancrypt_test

import (
	"path/filepath"
	"strings"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestOpenReturnsErrorForMissingLibrary(t *testing.T) {
	ctx, err := kalkancrypt.Open(filepath.Join(t.TempDir(), "missing-libkalkancrypt.so"))
	if err == nil {
		if ctx != nil {
			_ = ctx.Close()
		}
		t.Fatal("Open unexpectedly succeeded for a missing library")
	}
	if ctx != nil {
		t.Fatalf("Open returned context %#v with error %v", ctx, err)
	}
}

func TestOpenReturnsErrorForLibraryWithoutFunctionList(t *testing.T) {
	libc, ok := firstExistingFile(
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/usr/lib/aarch64-linux-gnu/libc.so.6",
	)
	if !ok {
		t.Skip("no system libc shared library found")
	}

	ctx, err := kalkancrypt.Open(libc)
	if err == nil {
		if ctx != nil {
			_ = ctx.Close()
		}
		t.Fatal("Open unexpectedly succeeded for libc")
	}
	if ctx != nil {
		t.Fatalf("Open returned context %#v with error %v", ctx, err)
	}
	if !strings.Contains(err.Error(), "KC_GetFunctionList") {
		t.Fatalf("Open(%q) error = %v, want KC_GetFunctionList lookup failure", libc, err)
	}
}
