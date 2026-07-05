//go:build linux && cgo

package kalkancrypt

import (
	"bytes"
	"testing"
)

func TestInputBytesAddsTerminatorAndKeepsLogicalLength(t *testing.T) {
	buf, size, err := inputBytes([]byte("abc"))
	if err != nil {
		t.Fatalf("inputBytes returned error: %v", err)
	}
	if int(size) != 3 {
		t.Fatalf("logical size = %d, want 3", size)
	}
	if !bytes.Equal(buf, []byte{'a', 'b', 'c', 0}) {
		t.Fatalf("buffer = %v, want NUL-terminated abc", buf)
	}

	empty, emptySize, err := inputBytes(nil)
	if err != nil {
		t.Fatalf("inputBytes(nil) returned error: %v", err)
	}
	if int(emptySize) != 0 {
		t.Fatalf("empty logical size = %d, want 0", emptySize)
	}
	if !bytes.Equal(empty, []byte{0}) {
		t.Fatalf("empty buffer = %v, want one NUL byte", empty)
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
