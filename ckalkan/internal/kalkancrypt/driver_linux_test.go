//go:build linux && cgo

package kalkancrypt

import "testing"

func TestLinuxDriverCloseHandlesNilHandle(t *testing.T) {
	var nilDriver *linuxDriver
	if err := nilDriver.Close(); err != nil {
		t.Fatalf("nil driver Close returned error: %v", err)
	}

	if err := (&linuxDriver{}).Close(); err != nil {
		t.Fatalf("empty driver Close returned error: %v", err)
	}
}

func TestDLErrorStringReturnsFallback(t *testing.T) {
	if got := dlerrorString("fallback error"); got != "fallback error" {
		t.Fatalf("dlerrorString fallback = %q, want fallback error", got)
	}
}

func TestCStringRejectsEmbeddedNUL(t *testing.T) {
	ptr, free, err := cString("bad\x00value")
	if err == nil {
		if free != nil {
			free()
		}
		t.Fatalf("cString returned ptr=%v, want embedded NUL error", ptr)
	}
}

func TestPointerHelpersReturnNilForEmptyBuffers(t *testing.T) {
	if ptr := charPtr(nil); ptr != nil {
		t.Fatalf("charPtr(nil) = %v, want nil", ptr)
	}
	if ptr := ucharPtr(nil); ptr != nil {
		t.Fatalf("ucharPtr(nil) = %v, want nil", ptr)
	}
	if ptr := charPtr([]byte("x")); ptr == nil {
		t.Fatal("charPtr(non-empty) returned nil")
	}
	if ptr := ucharPtr([]byte("x")); ptr == nil {
		t.Fatal("ucharPtr(non-empty) returned nil")
	}
}
