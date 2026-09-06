package ckalkan

import (
	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
	"github.com/skarm/kalkan/internal/nativebytes"
)

// SignWSSE returns in-memory XML with a native WS-Security signature for
// req.SignNodeID. The returned bytes exclude the native NUL terminator.
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

	initial := c.config.signedXMLOutputInitialCapacity(req.OutputCapacity, req.XML)

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

	return nativebytes.BeforeNUL(out), nil
}
