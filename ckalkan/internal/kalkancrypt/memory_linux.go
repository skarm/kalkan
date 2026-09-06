//go:build linux && amd64 && cgo

package kalkancrypt

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

// nativeInt matches the length type accepted by the Linux C ABI.
type nativeInt = C.int

// cString allocates a validated NUL-terminated C string. On success, the caller
// must invoke the returned cleanup function exactly once.
func cString(value string) (*C.char, func(), error) {
	if err := checkNativeString(value); err != nil {
		return nil, nil, err
	}

	ptr := C.CString(value)

	return ptr, func() { C.free(unsafe.Pointer(ptr)) }, nil
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
