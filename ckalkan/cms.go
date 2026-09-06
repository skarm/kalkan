package ckalkan

import (
	"time"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

// GetCertFromCMS returns a signer certificate extracted from in-memory CMS.
// Linux SDK 2.0.13 numbers certificates from 1; 0 returns an empty result.
// This differs from the signer index used by GetTimeFromSig.
// The CMS argument must contain the container bytes; KC_IN_FILE is ignored by
// that SDK operation, so callers must read file contents themselves.
func (c *Client) GetCertFromCMS(cms []byte, signID int, flags Flag) ([]byte, error) {
	if err := validateNativeSignerID("signID", signID); err != nil {
		return nil, err
	}

	nativeFlags, err := flagsToNativeInt(flags)
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[cmsContext](c, "GetCertFromCMS")
	if err != nil {
		return nil, err
	}

	return c.callBufferWithCapacityLocked("GetCertFromCMS", c.config.outputInitialCapacity(initialCertOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.GetCertFromCMS(kalkancrypt.GetCertFromCMSCall{
			CMS:      cms,
			SignID:   signID,
			Flags:    nativeFlags,
			Capacity: capacity,
		})
	})
}

// GetTimeFromSig returns the timestamp embedded for CMS signer sigID.
// The index is zero-based; a native failure returns the zero time and an error.
func (c *Client) GetTimeFromSig(data []byte, flags Flag, sigID int) (time.Time, error) {
	if err := validateNativeSignerID("sigID", sigID); err != nil {
		return time.Time{}, err
	}

	nativeFlags, err := flagsToNativeInt(flags)
	if err != nil {
		return time.Time{}, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[cmsContext](c, "GetTimeFromSig")
	if err != nil {
		return time.Time{}, err
	}

	c.clearErrorLocked()

	code, unix := ctx.GetTimeFromSig(data, nativeFlags, sigID)
	if err := c.wrapCodeLocked(ErrorCode(code)); err != nil {
		return time.Time{}, err
	}

	return time.Unix(unix, 0), nil
}
