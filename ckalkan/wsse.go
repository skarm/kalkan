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

	initial := c.config.requestOutputInitialCapacity(req.OutputCapacity, initialSignatureBuffer)

	return c.callBufferWithCapacityLocked(initial, func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.SignWSSE(kalkancrypt.SignWSSECall{
			Alias:      req.Alias,
			Flags:      flags,
			XML:        req.XML,
			SignNodeID: req.SignNodeID,
			Capacity:   capacity,
		})
	})
}
