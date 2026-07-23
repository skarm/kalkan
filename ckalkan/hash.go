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

	initial := initialHashOutputCapacity(algorithm, flags)

	return c.callBufferWithCapacityLocked("HashData", c.config.outputInitialCapacity(initial), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.HashData(kalkancrypt.HashDataCall{
			Algorithm: string(algorithm),
			Flags:     nativeFlags,
			Data:      data,
			Capacity:  capacity,
		})
	})
}

func initialHashOutputCapacity(algorithm HashAlgorithm, flags Flag) int {
	if flags&(OutBase64|OutPEM) != 0 {
		return initialEncodedHashCapacity
	}

	switch algorithm {
	case SHA256, GOST95, GOST2015_256:
		return initialRawHash256Capacity
	case GOST2015_512:
		return initialRawHash512Capacity
	default:
		// HashAlgorithm is extensible. Preserve the historical initial capacity
		// for algorithms whose digest length is not known by this package.
		return initialUnknownHashCapacity
	}
}
