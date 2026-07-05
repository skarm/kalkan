package ckalkan

import "fmt"

func validateNativeSignerID(field string, value int) error {
	if value < 0 {
		return fmt.Errorf("ckalkan: %s %d must be non-negative", field, value)
	}

	if value > maxNativeCInt {
		return fmt.Errorf("ckalkan: %s %d must be in range 0..%d for native C int", field, value, maxNativeCInt)
	}

	return nil
}
