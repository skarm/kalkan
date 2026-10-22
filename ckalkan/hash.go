package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// HashData returns the digest of data with algorithm and flags.
// The flags argument selects native input and output representations.
// algorithm uses a KalkanCrypt name such as [SHA256].
// [InFile] selects a file path.
// [InBase64] requests base64 conversion before the hash calculation.
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
		// Unknown algorithms use a default capacity because the wrapper cannot
		// estimate their digest length.
		// Native output lengths control retries.
		return initialUnknownHashCapacity
	}
}
