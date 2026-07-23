//go:build linux && cgo

package kalkancrypt

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func cString(value string) (*C.char, func(), error) {
	if err := checkNativeString(value); err != nil {
		return nil, nil, err
	}

	ptr := C.CString(value)

	return ptr, func() { C.free(unsafe.Pointer(ptr)) }, nil
}

// inputBytes validates a length-delimited native input without copying it.
// KalkanCrypt consumes the pointer synchronously, and every caller keeps the
// slice alive until the native call returns.
func inputBytes(value []byte) ([]byte, C.int, error) {
	if err := checkNativeBytes(value); err != nil {
		return nil, 0, err
	}

	return value, C.int(len(value)), nil
}

// filePathBytes returns a NUL-terminated copy for native parameters that are
// interpreted as file paths instead of length-delimited byte sequences.
func filePathBytes(value []byte) ([]byte, C.int, error) {
	if err := checkNativeBytes(value); err != nil {
		return nil, 0, err
	}

	buf := make([]byte, len(value)+1)
	copy(buf, value)

	return buf, C.int(len(value)), nil
}

func inputBytesWithFlags(value []byte, flags int) ([]byte, C.int, error) {
	if flags&inFileFlag != 0 {
		return filePathBytes(value)
	}

	return inputBytes(value)
}

func charPtr(buf []byte) *C.char {
	if len(buf) == 0 {
		return nil
	}

	return (*C.char)(unsafe.Pointer(&buf[0]))
}

func ucharPtr(buf []byte) *C.uchar {
	if len(buf) == 0 {
		return nil
	}

	return (*C.uchar)(unsafe.Pointer(&buf[0]))
}
