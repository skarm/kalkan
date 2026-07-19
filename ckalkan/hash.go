package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// HashData calls HashData and returns the native digest. The algorithm value is
// passed as KalkanCrypt expects it, for example SHA256.
func (c *Client) HashData(algorithm HashAlgorithm, flags Flag, data []byte) ([]byte, error) {
	nativeFlags, err := flagsToNativeInt(flags)
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[hashContext](c, "HashData")
	if err != nil {
		return nil, err
	}

	return c.callBufferWithCapacityLocked("HashData", c.config.outputInitialCapacity(initialHashOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.HashData(kalkancrypt.HashDataCall{
			Algorithm: string(algorithm),
			Flags:     nativeFlags,
			Data:      data,
			Capacity:  capacity,
		})
	})
}
