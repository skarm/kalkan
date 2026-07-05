package ckalkan

import (
	"time"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

// GetCertFromCMS calls KC_GetCertFromCMS and extracts a signer certificate from CMS.
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

	return c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(initialCertOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.GetCertFromCMS(cms, signID, nativeFlags, capacity)
	})
}

// GetTimeFromSig calls KC_GetTimeFromSig and returns the timestamp embedded in a signature.
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
