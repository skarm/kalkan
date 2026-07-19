package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// SignWSSE calls SignWSSE and returns the WS-Security signature envelope/body.
func (c *Client) SignWSSE(req SignWSSERequest) ([]byte, error) {
	flags, err := flagsToNativeUnsignedLong(req.Flags)
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[xmlContext](c, "SignWSSE")
	if err != nil {
		return nil, err
	}

	estimated, err := estimateSignedXMLOutput(req.XML, "SignWSSE")
	if err != nil {
		return nil, err
	}

	initial := c.config.estimatedOutputInitialCapacity(req.OutputCapacity, estimated, initialSignatureBuffer)

	out, err := c.callBufferWithCapacityLocked("SignWSSE", initial, func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.SignWSSE(kalkancrypt.SignWSSECall{
			Alias:      req.Alias,
			Flags:      flags,
			XML:        req.XML,
			SignNodeID: req.SignNodeID,
			Capacity:   capacity,
		})
	})
	if err != nil {
		return nil, err
	}

	return bytesBeforeNULTerminator(out), nil
}
