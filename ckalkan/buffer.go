package ckalkan

import (
	"bytes"
	"fmt"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func (c *Client) callListLocked(operation string, call kalkancrypt.ListBufferFunc) (ListResult, error) {
	size := normalizeConfiguredBufferSize(c.config.listBufferSize, defaultListBufferSize)
	if size > outputBufferLimit(c.config.maxBufferSize) {
		requested, ok := nonNegativeIntToUint64(size)
		if !ok {
			return ListResult{}, invalidNativeOutputLength(operation+" buffer capacity", size)
		}

		return ListResult{}, outputBufferLimitError(operation, c.config.maxBufferSize, requested)
	}

	for {
		c.clearErrorLocked()

		result, err := call(size)
		if err != nil {
			return ListResult{}, err
		}

		code := ErrorCode(result.Code)
		if code == ErrorBufferTooSmall || (code == ErrorOK && len(result.Data) == size) {
			newSize := growCapacity(size, 0, c.config.maxBufferSize)
			if newSize == size {
				return ListResult{}, outputBufferLimitError(operation, c.config.maxBufferSize, minimumOutputGrowth(size, 0))
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

func (c *Client) callBufferWithCapacityLocked(operation string, initial int, call kalkancrypt.OutputBufferFunc) ([]byte, error) {
	size := boundedOutputCapacity(initial, c.config.maxBufferSize)

	for {
		c.clearErrorLocked()

		result, err := call(size)
		if err != nil {
			return nil, err
		}

		code := ErrorCode(result.Code)
		if shouldRetryOutput(code, result.OutLen, size) {
			if result.OutLen < 0 {
				return nil, invalidNativeOutputLength("output", result.OutLen)
			}

			if result.OutLen > outputBufferLimit(c.config.maxBufferSize) {
				return nil, outputBufferLimitError(operation, c.config.maxBufferSize, uint64(result.OutLen))
			}

			newSize, grown := growReportedCapacity(size, result.OutLen, c.config.maxBufferSize)
			if !grown {
				return nil, outputBufferLimitError(
					operation,
					c.config.maxBufferSize,
					minimumOutputGrowth(size, result.OutLen),
				)
			}

			size = newSize

			continue
		}

		if result.OutLen < 0 {
			return nil, invalidNativeOutputLength("output", result.OutLen)
		}

		if err := c.wrapCodeLocked(code); err != nil {
			return nil, err
		}

		if err := validateNativeOutputDataLength("output", result.Data, result.OutLen); err != nil {
			return nil, err
		}

		return capacityLimitedBytes(result.Data), nil
	}
}

func shouldRetryOutput(code ErrorCode, reportedLength, capacity int) bool {
	return code == ErrorBufferTooSmall || (code == ErrorOK && reportedLength > capacity)
}

func outputNeedsGrowth(code ErrorCode, reportedLength, capacity int, retrySaturated bool) bool {
	return reportedLength > capacity ||
		code == ErrorBufferTooSmall && reportedLength >= capacity ||
		code == ErrorOK && retrySaturated && reportedLength == capacity
}

type outputBufferState struct {
	current        int
	reported       int
	active         bool
	retrySaturated bool
	growthHint     int
}

func nextOutputBufferCapacities(operation string, code ErrorCode, hardMaximum int, outputs ...outputBufferState) ([]int, error) {
	grow := make([]bool, len(outputs))
	hasGrowthCandidate := false

	for index, output := range outputs {
		if output.active && output.reported < 0 {
			return nil, invalidNativeOutputLength(operation+" output", output.reported)
		}

		grow[index] = output.active && outputNeedsGrowth(
			code,
			output.reported,
			output.current,
			output.retrySaturated,
		)
		hasGrowthCandidate = hasGrowthCandidate || grow[index]
	}

	// Some SDK paths return only KCR_BUFFER_TOO_SMALL without useful output
	// lengths. In that ambiguous case every active output must grow.
	if code == ErrorBufferTooSmall && !hasGrowthCandidate {
		for index, output := range outputs {
			grow[index] = output.active
		}
	}

	reported := uint64(0)
	limit := outputBufferLimit(hardMaximum)

	for index, output := range outputs {
		if !grow[index] {
			continue
		}

		reportedSize, ok := nonNegativeIntToUint64(output.reported)
		if !ok {
			return nil, invalidNativeOutputLength(operation+" output", output.reported)
		}

		reported = max(reported, reportedSize)
		if output.reported > limit {
			return nil, outputBufferLimitError(operation, hardMaximum, reported)
		}
	}

	next := make([]int, len(outputs))
	grew := false

	for index, output := range outputs {
		next[index] = output.current
		if !grow[index] {
			continue
		}

		required := output.reported
		if required >= output.current {
			required = max(required, output.growthHint)
		}

		var outputGrew bool

		next[index], outputGrew = growReportedCapacity(output.current, required, hardMaximum)
		grew = grew || outputGrew
	}

	if !grew {
		requested := reported

		for index, output := range outputs {
			if grow[index] {
				requested = max(requested, minimumOutputGrowth(output.current, output.reported))
			}
		}

		return nil, outputBufferLimitError(operation, hardMaximum, requested)
	}

	return next, nil
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

	return max(size, conservativeOutputBufferSize)
}

func boundedOutputCapacity(value, maximum int) int {
	size := value
	if size <= 0 {
		size = defaultOutputBufferSize
	}

	maximum = outputBufferLimit(maximum)

	return min(size, maximum)
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

func outputBufferLimit(hardMaximum int) int {
	if hardMaximum > 0 {
		return min(hardMaximum, maxNativeOutputBufferSize)
	}

	return DefaultMaxOutputBufferSize
}

func growCapacity(current, requested, maximum int) int {
	limit := outputBufferLimit(maximum)
	if current >= limit {
		return current
	}

	next := limit
	if current <= limit/2 {
		next = current * 2
	}

	if requested > current {
		next = requested
	}

	if next > limit {
		return limit
	}

	return next
}

func outputBufferLimitError(operation string, hardMaximum int, requested uint64) error {
	limitValue := outputBufferLimit(hardMaximum)

	limit, ok := nonNegativeIntToUint64(limitValue)
	if !ok {
		return fmt.Errorf("ckalkan: output buffer limit is negative: %d", limitValue)
	}

	return &OutputBufferLimitError{
		Operation: operation,
		Requested: requested,
		Limit:     limit,
	}
}

func nonNegativeIntToUint64(value int) (uint64, bool) {
	if value < 0 {
		return 0, false
	}

	return uint64(value), true
}

func minimumOutputGrowth(current, reported int) uint64 {
	if reported > current {
		value, ok := nonNegativeIntToUint64(reported)
		if ok {
			return value
		}
	}

	if current <= 0 {
		return 1
	}

	value, ok := nonNegativeIntToUint64(current)
	if !ok {
		return 1
	}

	// Add after converting so this remains safe when int is 32 bits and the
	// current capacity is the largest value representable by the C int ABI.
	return value + 1
}

func outputBufferSafetyMinimumError(operation string, hardMaximum, minimum int) error {
	return &KalkanError{
		Code: ErrorBufferTooSmall,
		Message: fmt.Sprintf(
			"%s requires a native safety buffer of at least %d bytes, exceeding configured hard limit %d",
			operation,
			minimum,
			hardMaximum,
		),
	}
}

func invalidNativeOutputLength(output string, length int) error {
	return fmt.Errorf("ckalkan: native %s length is negative: %d", output, length)
}

func validateNativeOutputDataLength(output string, data []byte, reportedLength int) error {
	if len(data) != reportedLength {
		return fmt.Errorf(
			"ckalkan: native %s data length %d does not match reported length %d",
			output,
			len(data),
			reportedLength,
		)
	}

	return nil
}

func capacityLimitedBytes(value []byte) []byte {
	return value[:len(value):len(value)]
}

// bytesBeforeNULTerminator decodes an output whose native contract is textual.
// Some KalkanCrypt methods report a fixed-size block rather than the C-string
// length, so bytes after the first NUL are unspecified and must be ignored.
func bytesBeforeNULTerminator(value []byte) []byte {
	index := bytes.IndexByte(value, 0)
	if index >= 0 {
		return value[:index:index]
	}

	return capacityLimitedBytes(value)
}
