package ckalkan

import "fmt"

const (
	maxNativeCInt         = int(^uint32(0) >> 1)
	maxNativeUnsignedLong = uint64(^uint32(0))
)

func validateNativeSignedRange(field string, value int64, upperBound uint64, nativeType string) (uint64, error) {
	if value < 0 {
		return 0, fmt.Errorf("ckalkan: %s %d must be non-negative for %s", field, value, nativeType)
	}

	return validateNativeUnsignedRange(field, uint64(value), upperBound, nativeType)
}

func validateNativeUnsignedRange(field string, value, upperBound uint64, nativeType string) (uint64, error) {
	if value > upperBound {
		return 0, fmt.Errorf("ckalkan: %s %d must be in range 0..%d for %s", field, value, upperBound, nativeType)
	}

	return value, nil
}
