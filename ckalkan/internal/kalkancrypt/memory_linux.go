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

// inputBytes returns a NUL-terminated Go-owned byte buffer and the logical
// length passed to KalkanCrypt. The extra NUL preserves compatibility with
// native code that treats a length-delimited parameter as a C string.
func inputBytes(value []byte) ([]byte, C.int, error) {
	if err := checkNativeBytes(value); err != nil {
		return nil, 0, err
	}

	buf := make([]byte, len(value)+1)
	copy(buf, value)

	return buf, C.int(len(value)), nil
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
