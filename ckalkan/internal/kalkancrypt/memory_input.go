package kalkancrypt

import (
	"bytes"
	"errors"
)

// inputBytes validates a length-delimited native input without copying it.
// KalkanCrypt consumes the pointer synchronously, and every caller keeps the
// slice alive until the native call returns.
func inputBytes(value []byte) ([]byte, nativeInt, error) {
	if err := checkNativeBytes(value); err != nil {
		return nil, 0, err
	}

	return value, nativeInt(len(value)), nil //nolint:gosec // checkNativeBytes rejects lengths above math.MaxInt32.
}

// filePathBytes returns a NUL-terminated copy for native parameters that are
// interpreted as file paths instead of length-delimited byte sequences.
func filePathBytes(value []byte) ([]byte, nativeInt, error) {
	if err := checkNativeBytes(value); err != nil {
		return nil, 0, err
	}

	if bytes.IndexByte(value, 0) >= 0 {
		return nil, 0, errors.New("kalkancrypt: file path contains embedded NUL")
	}

	return terminatedInputBytes(value)
}

// terminatedInputBytes owns the terminator without changing the logical length.
func terminatedInputBytes(value []byte) ([]byte, nativeInt, error) {
	if err := checkNativeBytes(value); err != nil {
		return nil, 0, err
	}

	buf := make([]byte, len(value)+1)
	copy(buf, value)

	return buf, nativeInt(len(value)), nil //nolint:gosec // checkNativeBytes rejects lengths above math.MaxInt32.
}

func inputBytesWithFlags(value []byte, flags int) ([]byte, nativeInt, error) {
	if flags&inFileFlag != 0 {
		return filePathBytes(value)
	}

	return inputBytes(value)
}

// cmsInputBytes terminates Base64 inputs consumed as C strings by the Linux
// SDK 2.0.13 CMS routines even though their ABI also accepts an explicit length.
// Keep this input contract consistent across native drivers.
func cmsInputBytes(value []byte, flags int) ([]byte, nativeInt, error) {
	if flags&inFileFlag != 0 {
		return filePathBytes(value)
	}

	if flags&inBase64Flag != 0 {
		return terminatedInputBytes(value)
	}

	return inputBytes(value)
}

func verifySignatureInput(signature []byte, flags int, universal bool) ([]byte, nativeInt, error) {
	if universal {
		// UVerifyData in the verified Linux SDK always interprets Signature as
		// the path to a signature or container file, independently of flags.
		return filePathBytes(signature)
	}

	return cmsInputBytes(signature, flags)
}
