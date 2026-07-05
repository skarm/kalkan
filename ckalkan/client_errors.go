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
		message := string(trimCStringBytes(result.Data))

		if code == ErrorBufferTooSmall || (code == ErrorOK && result.OutLen > size) {
			newSize := growCapacity(size, result.OutLen, c.config.maxBufferSize)
			if newSize != size {
				size = newSize

				continue
			}
		}

		return code, message
	}
}
