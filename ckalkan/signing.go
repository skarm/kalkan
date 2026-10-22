package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// SignHash signs a precomputed hash with the loaded key selected by alias.
// The hash algorithm must match the algorithm required by the loaded signing key.
// The Linux SDK derives the signing algorithm from that key and ignores the
// HashSHA256, HashGOST95, HashGOST2015_256, and HashGOST2015_512 flags here.
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

// SignData signs req.Data with the native flags and returns the signature bytes.
// A nil req.Signature creates a new signature.
// An existing signature can receive another signer when the native mode supports it.
func (c *Client) SignData(req SignDataRequest) ([]byte, error) {
	nativeFlags, err := flagsToNativeInt(req.Flags)
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[cmsContext](c, "SignData")
	if err != nil {
		return nil, err
	}

	estimated := 0
	if req.OutputCapacity <= 0 {
		estimated = estimateSignDataOutput(req, c.config.maxBufferSize)
	}

	initial := c.config.estimatedOutputInitialCapacity(req.OutputCapacity, estimated, initialSignatureBuffer)

	return c.callBufferWithCapacityLocked("SignData", initial, func(capacity int) (kalkancrypt.BufferResult, error) {
		result, err := ctx.SignData(kalkancrypt.SignDataCall{
			Alias:     req.Alias,
			Flags:     nativeFlags,
			Data:      req.Data,
			Signature: req.Signature,
			Capacity:  capacity,
		})
		// The Linux SDK can return KCR_OK after a signature or TSA failure.
		// KC_GetLastError can contain the only failure report.
		// Reject untouched or incomplete output buffers.
		if err == nil && result.Code == uint64(ErrorOK) {
			result.Code = uint64(platformCMSLastError(ctx))
		}

		return result, err
	})
}
