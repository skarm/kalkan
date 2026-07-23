//go:build (linux && cgo) || (windows && amd64)

package kalkancrypt

import (
	"bytes"
	"testing"
)

func TestInputBytesReusesLengthDelimitedInput(t *testing.T) {
	value := []byte("abc")

	buf, size, err := inputBytes(value)
	if err != nil {
		t.Fatalf("inputBytes returned error: %v", err)
	}
	if int(size) != len(value) {
		t.Fatalf("logical size = %d, want %d", size, len(value))
	}
	if !bytes.Equal(buf, value) {
		t.Fatalf("buffer = %v, want %v", buf, value)
	}
	if &buf[0] != &value[0] {
		t.Fatal("inputBytes copied a length-delimited input")
	}

	empty, emptySize, err := inputBytes(nil)
	if err != nil {
		t.Fatalf("inputBytes(nil) returned error: %v", err)
	}
	if int(emptySize) != 0 {
		t.Fatalf("empty logical size = %d, want 0", emptySize)
	}
	if empty != nil {
		t.Fatalf("empty buffer = %v, want nil", empty)
	}
}

func TestInputBytesDoesNotInspectSpareCapacity(t *testing.T) {
	backing := []byte{'a', 'b', 'c', 'x'}
	value := backing[:3]

	buf, size, err := inputBytes(value)
	if err != nil {
		t.Fatalf("inputBytes returned error: %v", err)
	}
	if int(size) != len(value) {
		t.Fatalf("logical size = %d, want %d", size, len(value))
	}
	if len(buf) != len(value) {
		t.Fatalf("buffer length = %d, want %d", len(buf), len(value))
	}
	if &buf[0] != &value[0] {
		t.Fatal("inputBytes copied input with nonzero spare capacity")
	}
}

func TestFilePathBytesAddsTerminatorAndCopiesInput(t *testing.T) {
	value := []byte("abc")

	buf, size, err := filePathBytes(value)
	if err != nil {
		t.Fatalf("filePathBytes returned error: %v", err)
	}
	if int(size) != len(value) {
		t.Fatalf("logical size = %d, want %d", size, len(value))
	}
	if &buf[0] == &value[0] {
		t.Fatal("filePathBytes reused caller storage")
	}
	if !bytes.Equal(buf, []byte{'a', 'b', 'c', 0}) {
		t.Fatalf("buffer = %v, want copied NUL-terminated abc", buf)
	}

	empty, emptySize, err := filePathBytes(nil)
	if err != nil {
		t.Fatalf("filePathBytes(nil) returned error: %v", err)
	}
	if int(emptySize) != 0 || !bytes.Equal(empty, []byte{0}) {
		t.Fatalf("empty file input = %v/%d, want [0]/0", empty, emptySize)
	}
}

func TestInputBytesWithFlagsCopiesOnlyFilePaths(t *testing.T) {
	value := []byte("abc")

	memoryInput, _, err := inputBytesWithFlags(value, 0)
	if err != nil {
		t.Fatalf("memory input returned error: %v", err)
	}
	if &memoryInput[0] != &value[0] {
		t.Fatal("memory input was copied")
	}

	fileInput, _, err := inputBytesWithFlags(value, inFileFlag)
	if err != nil {
		t.Fatalf("file input returned error: %v", err)
	}
	if &fileInput[0] == &value[0] {
		t.Fatal("file input was not copied")
	}
	if fileInput[len(value)] != 0 {
		t.Fatal("file input lacks a trailing NUL")
	}
}

func TestVerifySignatureInputTreatsUniversalInputAsFilePath(t *testing.T) {
	value := []byte("signature.cms")

	signature, _, err := verifySignatureInput(value, 0, true)
	if err != nil {
		t.Fatalf("verifySignatureInput returned error: %v", err)
	}
	if &signature[0] == &value[0] {
		t.Fatal("universal signature path was not copied")
	}
	if signature[len(value)] != 0 {
		t.Fatal("universal signature path lacks a trailing NUL")
	}
}
