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
