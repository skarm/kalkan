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

	return c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(initialSignatureBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.SignHash(alias, nativeFlags, hash, capacity)
	})
}

// SignData calls SignData. signature may be nil for a new signature, or it may
// contain an existing CMS signature when appending according to KalkanCrypt flags.
func (c *Client) SignData(alias string, flags Flag, data, signature []byte) ([]byte, error) {
	nativeFlags, err := flagsToNativeInt(flags)
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[cmsContext](c, "SignData")
	if err != nil {
		return nil, err
	}

	return c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(initialSignatureBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.SignData(alias, nativeFlags, data, signature, capacity)
	})
}
