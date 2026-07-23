//go:build windows && amd64

package kalkancrypt

import (
	"unsafe"
)

func narrowString(value string) ([]byte, error) {
	if err := checkNativeString(value); err != nil {
		return nil, err
	}

	// KalkanCrypt Windows calls receive narrow char* arguments. The wrapper
	// passes Go's UTF-8 string bytes plus a terminating NUL; deployments should
	// verify this matches their SDK/DLL version if paths or aliases contain
	// non-ASCII characters.
	buf := make([]byte, len(value)+1)
	copy(buf, value)

	return buf, nil
}

// inputBytes validates a length-delimited native input without copying it.
// KalkanCrypt consumes the pointer synchronously, and every caller keeps the
// slice alive until the native call returns.
func inputBytes(value []byte) ([]byte, int32, error) {
	if err := checkNativeBytes(value); err != nil {
		return nil, 0, err
	}

	return value, int32(len(value)), nil
}

// filePathBytes returns a NUL-terminated copy for native parameters that are
// interpreted as file paths instead of length-delimited byte sequences.
func filePathBytes(value []byte) ([]byte, int32, error) {
	if err := checkNativeBytes(value); err != nil {
		return nil, 0, err
	}

	buf := make([]byte, len(value)+1)
	copy(buf, value)

	return buf, int32(len(value)), nil
}

func inputBytesWithFlags(value []byte, flags int) ([]byte, int32, error) {
	if flags&inFileFlag != 0 {
		return filePathBytes(value)
	}

	return inputBytes(value)
}

func bytesPtr(buf []byte) uintptr {
	if len(buf) == 0 {
		return 0
	}

	return uintptr(unsafe.Pointer(&buf[0]))
}

func int32Ptr(value *int32) uintptr {
	return uintptr(unsafe.Pointer(value))
}

func uint32Ptr(value *uint32) uintptr {
	return uintptr(unsafe.Pointer(value))
}

func int64Ptr(value *int64) uintptr {
	return uintptr(unsafe.Pointer(value))
}

func intArg(value int) uintptr {
	return uintptr(uint32(value))
}

func ulongArg(value uint64) uintptr {
	return uintptr(uint32(value))
}
