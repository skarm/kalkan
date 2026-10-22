package ckalkan

import (
	"time"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

// GetCertFromCMS returns the certificate selected by signID from cms.
// The Linux SDK numbers certificates from 1.
// Index 0 returns an empty result.
// This differs from the signer index in [Client.GetTimeFromSig].
//
// cms must contain container bytes.
// The Linux SDK ignores KC_IN_FILE for this operation.
// Read file contents before this call.
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

// GetTimeFromSig returns the embedded timestamp for CMS signer sigID.
// Extraction does not authenticate the CMS or TSA signature.
// Verify the CMS with [Client.VerifyData] before you trust the timestamp.
//
// The index is zero-based.
// A native failure returns the zero time and an error.
// The Linux SDK expects CMS contents and ignores InFile for this operation.
// Read file contents before this call when that SDK is in use.
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
