package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// SignHash calls SignHash and signs an already calculated hash with a loaded key.
func (c *Client) SignHash(alias string, flags Flag, hash []byte) ([]byte, error) {
	nativeFlags, err := flagsToNativeInt(flags)
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[hashContext](c, "SignHash")
	if err != nil {
		return nil, err
	}

	return c.callBufferWithCapacityLocked("SignHash", c.config.outputInitialCapacity(initialSignatureBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.SignHash(kalkancrypt.SignHashCall{
			Alias:    alias,
			Flags:    nativeFlags,
			Hash:     hash,
			Capacity: capacity,
		})
	})
}

// SignData calls SignData. Signature may be nil for a new signature, or it may
// contain an existing CMS signature when appending according to KalkanCrypt flags.
func (c *Client) SignData(req SignDataRequest) ([]byte, error) {
	nativeFlags, err := flagsToNativeInt(req.Flags)
	if err != nil {
		return nil, err
	}

	estimated, err := estimateSignDataOutput(req)
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[cmsContext](c, "SignData")
	if err != nil {
		return nil, err
	}

	initial := c.config.estimatedOutputInitialCapacity(req.OutputCapacity, estimated, initialSignatureBuffer)

	return c.callBufferWithCapacityLocked("SignData", initial, func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.SignData(kalkancrypt.SignDataCall{
			Alias:     req.Alias,
			Flags:     nativeFlags,
			Data:      req.Data,
			Signature: req.Signature,
			Capacity:  capacity,
		})
	})
}
