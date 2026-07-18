package kalkancrypt

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"
)

const errorParam uint64 = 0x08f00300

func outputBuffer(size int) ([]byte, error) {
	if err := checkOutputBufferCapacity(size); err != nil {
		return nil, err
	}

	return make([]byte, size), nil
}

func checkOutputBufferCapacity(size int) error {
	if size <= 0 {
		return fmt.Errorf("kalkancrypt: invalid buffer size %d", size)
	}

	if size > math.MaxInt32 {
		return fmt.Errorf("kalkancrypt: buffer size %d overflows native C int", size)
	}

	return nil
}

func checkNativeInputLength(length int64) error {
	if length < 0 {
		return fmt.Errorf("kalkancrypt: invalid negative input length %d", length)
	}

	if length > math.MaxInt32 {
		return fmt.Errorf("kalkancrypt: input length %d overflows native C int", length)
	}

	return nil
}

func checkNativeBytes(value []byte) error {
	return checkNativeInputLength(int64(len(value)))
}

func checkNativeString(value string) error {
	if strings.ContainsRune(value, '\x00') {
		return errors.New("kalkancrypt: string contains embedded NUL")
	}

	return checkNativeInputLength(int64(len(value)))
}

func boundedBytes(buf []byte, length int) []byte {
	if len(buf) == 0 || length <= 0 {
		return nil
	}

	if length > len(buf) {
		length = len(buf)
	}

	return buf[:length:length]
}

// bytesBeforeNULTerminator is used only by native APIs that return a C string
// without a byte length. Bytes at and after the first NUL are not part of that
// string.
func bytesBeforeNULTerminator(value []byte) []byte {
	if i := bytes.IndexByte(value, 0); i >= 0 {
		return value[:i:i]
	}

	return value[:len(value):len(value)]
}
