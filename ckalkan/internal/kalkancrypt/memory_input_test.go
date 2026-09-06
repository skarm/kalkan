package kalkancrypt

import (
	"bytes"
	"fmt"
	"strings"
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

func TestFileInputsRejectEmbeddedNUL(t *testing.T) {
	value := []byte("payload\x00different")
	tests := []struct {
		name string
		call func() ([]byte, nativeInt, error)
	}{
		{name: "path", call: func() ([]byte, nativeInt, error) { return filePathBytes(value) }},
		{name: "file input", call: func() ([]byte, nativeInt, error) { return inputBytesWithFlags(value, inFileFlag) }},
		{name: "CMS file", call: func() ([]byte, nativeInt, error) { return cmsInputBytes(value, inFileFlag) }},
		{name: "Base64 CMS file", call: func() ([]byte, nativeInt, error) { return cmsInputBytes(value, inFileFlag|inBase64Flag) }},
		{name: "signature file", call: func() ([]byte, nativeInt, error) { return verifySignatureInput(value, inFileFlag, false) }},
		{name: "Base64 signature file", call: func() ([]byte, nativeInt, error) { return verifySignatureInput(value, inFileFlag|inBase64Flag, false) }},
		{name: "universal signature file", call: func() ([]byte, nativeInt, error) { return verifySignatureInput(value, 0, true) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf, length, err := test.call()
			if err == nil || !strings.Contains(err.Error(), "NUL") || buf != nil || length != 0 {
				t.Fatalf("file input = %v/%d, %v, want NUL rejection without a native input", buf, length, err)
			}
		})
	}
}

func TestMemoryInputsPreserveEmbeddedNUL(t *testing.T) {
	value := []byte{'a', 0, 'b'}
	for _, flags := range []int{0, 0x00000008, 0x00000004} {
		buf, length, err := cmsInputBytes(value, flags)
		if err != nil || int(length) != len(value) || !bytes.Equal(buf, value) {
			t.Fatalf("flags %x: memory input = %v/%d, %v, want original binary input", flags, buf, length, err)
		}
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

func TestCMSInputBytesTerminatesBase64WithoutChangingLength(t *testing.T) {
	for _, flags := range []int{0, 0x00000008, 0x00000004, inBase64Flag, inFileFlag, inFileFlag | inBase64Flag} {
		t.Run(fmt.Sprintf("flags_%x", flags), func(t *testing.T) {
			backing := []byte{'Y', 'W', 'J', 'j', 'x'}
			value := backing[:4]
			buf, size, err := cmsInputBytes(value, flags)
			if err != nil {
				t.Fatal(err)
			}
			if int(size) != len(value) || !bytes.Equal(buf[:len(value)], value) {
				t.Fatalf("input = %v/%d, want unchanged %v/%d", buf, size, value, len(value))
			}
			if flags&(inBase64Flag|inFileFlag) != 0 {
				if len(buf) != len(value)+1 || buf[len(value)] != 0 || &buf[0] == &value[0] {
					t.Fatalf("input = %v, want a separate NUL-terminated copy", buf)
				}
			} else if len(buf) != len(value) || &buf[0] != &value[0] {
				t.Fatal("raw, DER, or PEM input was copied or extended")
			}
			if backing[4] != 'x' {
				t.Fatal("input's spare capacity was modified")
			}
		})
	}
}
