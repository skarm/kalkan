package kalkan

import "fmt"

func (c *Client) configuredMaxInputSize() int64 {
	if c == nil {
		return 0
	}

	return c.config.maxInputSize
}

func validateMemorySourceSize(source Source, field string, maxSize int64) error {
	if maxSize <= 0 || source.file || !source.isSet() {
		return nil
	}

	return validateBytesSize(source.data, field, maxSize)
}

func validateBytesSize(data []byte, field string, maxSize int64) error {
	if maxSize <= 0 {
		return nil
	}

	if int64(len(data)) > maxSize {
		return fmt.Errorf("%w: %s exceeds maximum input size of %d bytes", ErrInvalidInput, field, maxSize)
	}

	return nil
}
