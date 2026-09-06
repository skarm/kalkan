//go:build windows && amd64

package kalkancrypt

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

// bytesPtr preserves pointer semantics until the syscall argument is evaluated.
// Empty inputs use a null pointer even when their backing array is nonempty.
func bytesPtr(buf []byte) *byte {
	if len(buf) == 0 {
		return nil
	}

	return &buf[0]
}

func intArg(value int) uintptr {
	return uintptr(uint32(value))
}

func ulongArg(value uint64) uintptr {
	return uintptr(uint32(value))
}
