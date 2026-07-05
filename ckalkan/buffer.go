package ckalkan

import (
	"bytes"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func (c *Client) callListLocked(call func(capacity int) (kalkancrypt.ListResult, error)) (ListResult, error) {
	size := boundedConfiguredBufferSize(c.config.listBufferSize, defaultListBufferSize, c.config.maxBufferSize)

	for {
		c.clearErrorLocked()

		result, err := call(size)
		if err != nil {
			return ListResult{}, err
		}

		code := ErrorCode(result.Code)
		if code == ErrorBufferTooSmall {
			newSize := growCapacity(size, 0, c.config.maxBufferSize)
			if newSize == size {
				return ListResult{}, c.wrapCodeLocked(code)
			}

			size = newSize

			continue
		}

		if err := c.wrapCodeLocked(code); err != nil {
			return ListResult{}, err
		}

		return ListResult{Data: result.Data, Count: result.Count}, nil
	}
}

func (c *Client) callBufferLocked(call func(capacity int) (kalkancrypt.BufferResult, error)) ([]byte, error) {
	return c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(defaultOutputBufferSize), call)
}

func (c *Client) callBufferWithCapacityLocked(initial int, call func(capacity int) (kalkancrypt.BufferResult, error)) ([]byte, error) {
	size := boundedOutputCapacity(initial, c.config.maxBufferSize)

	for {
		c.clearErrorLocked()

		result, err := call(size)
		if err != nil {
			return nil, err
		}

		code := ErrorCode(result.Code)
		if shouldRetryOutput(code, result.OutLen, size) {
			newSize, grown := growReportedCapacity(size, result.OutLen, c.config.maxBufferSize)
			if !grown {
				return nil, c.wrapCodeLocked(retryErrorCode(code))
			}

			size = newSize

			continue
		}

		if err := c.wrapCodeLocked(code); err != nil {
			return nil, err
		}

		return result.Data, nil
	}
}

func shouldRetryOutput(code ErrorCode, reportedLength, capacity int) bool {
	return code == ErrorBufferTooSmall || (code == ErrorOK && reportedLength > capacity)
}

func retryErrorCode(code ErrorCode) ErrorCode {
	if code == ErrorOK {
		return ErrorBufferTooSmall
	}

	return code
}

func growReportedCapacity(current, reported, maximum int) (int, bool) {
	next := growCapacity(current, reported, maximum)

	return next, next != current
}

func normalizeConfiguredBufferSize(value, fallback int) int {
	size := defaultOutputBufferSize

	if fallback > 0 {
		size = fallback
	}

	if value > 0 {
		size = value
	}

	if size < conservativeOutputBufferSize {
		return conservativeOutputBufferSize
	}

	return size
}

func boundedConfiguredBufferSize(value, fallback, maximum int) int {
	size := normalizeConfiguredBufferSize(value, fallback)
	maximum = normalizeMaxOutputBufferSize(maximum)

	if size > maximum {
		return maximum
	}

	return size
}

func boundedOutputCapacity(value, maximum int) int {
	size := value
	if size <= 0 {
		size = defaultOutputBufferSize
	}

	maximum = normalizeMaxOutputBufferSize(maximum)
	if size > maximum {
		return maximum
	}

	return size
}

func (c config) outputInitialCapacity(defaultInitial int) int {
	if c.bufferSize > 0 {
		return normalizeConfiguredBufferSize(c.bufferSize, defaultOutputBufferSize)
	}

	if defaultInitial > 0 {
		return defaultInitial
	}

	return defaultOutputBufferSize
}

func (c config) requestOutputInitialCapacity(requested, defaultInitial int) int {
	if requested > 0 {
		return requested
	}

	return c.outputInitialCapacity(defaultInitial)
}

func normalizeMaxOutputBufferSize(maximum int) int {
	if maximum <= 0 {
		maximum = defaultMaxOutputBufferSize
	}

	if maximum < conservativeOutputBufferSize {
		return conservativeOutputBufferSize
	}

	return maximum
}

func growCapacity(current, requested, maximum int) int {
	maximum = normalizeMaxOutputBufferSize(maximum)

	next := current * 2
	if requested > current {
		next = requested
	}

	if next < current {
		return current
	}

	if next > maximum {
		if current < maximum {
			return maximum
		}

		return current
	}

	return next
}

func trimCStringBytes(value []byte) []byte {
	if i := bytes.IndexByte(value, 0); i >= 0 {
		return value[:i]
	}

	return value
}
