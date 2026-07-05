//go:build windows && amd64

package kalkancrypt

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"
)

func TestWindowsFunctionListLayout(t *testing.T) {
	const fields = 31
	if got, want := unsafe.Sizeof(kcFunctionList{}), uintptr(fields)*unsafe.Sizeof(uintptr(0)); got != want {
		t.Fatalf("kcFunctionList size = %d, want %d", got, want)
	}
}

func TestWindowsOpenDriverMissingDLL(t *testing.T) {
	if _, err := openDriver(`Z:\kalkan-no-such\KalkanCrypt.dll`); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("openDriver missing DLL error = %v, want native load error", err)
	}
}

func TestWindowsMissingOptionalFunctionReturnsLibraryNotInitializedOnCall(t *testing.T) {
	if got := callWindowsStatus(0); got != errorLibraryNotInitialized {
		t.Fatalf("callWindowsStatus(0) = %#x, want %#x", got, uint64(errorLibraryNotInitialized))
	}
}

func TestWindowsNarrowStringUsesUTF8Bytes(t *testing.T) {
	got, err := narrowString("ключ")
	if err != nil {
		t.Fatalf("narrowString returned error: %v", err)
	}
	want := append([]byte("ключ"), 0)
	if !bytes.Equal(got, want) {
		t.Fatalf("narrowString bytes = %v, want UTF-8 bytes %v", got, want)
	}
}

func TestWindowsNarrowStringRejectsEmbeddedNUL(t *testing.T) {
	if _, err := narrowString("bad\x00value"); err == nil {
		t.Fatal("narrowString unexpectedly accepted embedded NUL")
	}
}
