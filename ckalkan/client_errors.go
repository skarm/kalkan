package ckalkan

import "strings"

func (c *Client) wrapCodeLocked(code ErrorCode) error {
	if code == ErrorOK {
		return nil
	}

	_, message := c.lastErrorStringLocked()

	return errorFromCode(code, strings.TrimSpace(message))
}

func (c *Client) lastErrorStringLocked() (ErrorCode, string) {
	if c == nil || c.ctx == nil {
		return ErrorLibraryNotInitialized, ErrClosed.Error()
	}

	size := boundedOutputCapacity(c.config.outputInitialCapacity(initialInfoOutputBuffer), c.config.maxBufferSize)

	for {
		result, err := c.ctx.LastErrorString(size)
		if err != nil {
			return ErrorMemory, err.Error()
		}

		code := ErrorCode(result.Code)

		if result.OutLen < 0 {
			return ErrorMemory, invalidNativeOutputLength("last-error string", result.OutLen).Error()
		}

		if code == ErrorBufferTooSmall || (code == ErrorOK && result.OutLen > size) {
			if result.OutLen > outputBufferLimit(c.config.maxBufferSize) {
				return ErrorBufferTooSmall, outputBufferLimitError("LastErrorString", c.config.maxBufferSize, uint64(result.OutLen)).Error()
			}

			newSize := growCapacity(size, result.OutLen, c.config.maxBufferSize)
			if newSize != size {
				size = newSize

				continue
			}

			return retryErrorCode(code), outputBufferLimitError("LastErrorString", c.config.maxBufferSize, minimumOutputGrowth(size, result.OutLen)).Error()
		}

		if code == ErrorOK {
			if err := validateNativeOutputDataLength("last-error string", result.Data, result.OutLen); err != nil {
				return ErrorMemory, err.Error()
			}
		}

		return code, string(bytesBeforeNULTerminator(result.Data))
	}
}
