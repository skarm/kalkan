package ckalkan

import (
	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
	"github.com/skarm/kalkan/internal/nativebytes"
)

// ZipConVerify verifies the KalkanCrypt container at zipFile and returns
// native diagnostic text. A nonzero native status returns an error.
func (c *Client) ZipConVerify(zipFile string, flags Flag) (string, error) {
	nativeFlags, err := flagsToNativeInt(flags)
	if err != nil {
		return "", err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[zipContext](c, "ZipConVerify")
	if err != nil {
		return "", err
	}

	safetyCapacity := platformZIPVerifySafetyCapacity()
	if c.config.maxBufferSize > 0 && c.config.maxBufferSize < safetyCapacity {
		return "", outputBufferSafetyMinimumError("ZipConVerify", c.config.maxBufferSize, safetyCapacity)
	}

	out, err := c.callBufferWithCapacityLocked("ZipConVerify", c.config.outputInitialCapacity(initialZIPVerifyBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.ZipConVerify(zipFile, nativeFlags, capacity)
	})
	if err != nil {
		return "", err
	}

	return string(nativebytes.BeforeNUL(out)), nil
}

// ZipConSign signs req.FilePath into a KalkanCrypt ZIP container named by
// req.Name in req.OutDir. Output creation and naming follow the native API;
// this method does not stage or atomically publish the file.
func (c *Client) ZipConSign(req ZipConSignRequest) error {
	nativeFlags, err := flagsToNativeInt(req.Flags)
	if err != nil {
		return err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[zipContext](c, "ZipConSign")
	if err != nil {
		return err
	}

	c.clearErrorLocked()

	return c.wrapCodeLocked(ErrorCode(ctx.ZipConSign(kalkancrypt.ZipConSignCall{
		Alias:    req.Alias,
		FilePath: req.FilePath,
		Name:     req.Name,
		OutDir:   req.OutDir,
		Flags:    nativeFlags,
	})))
}

// GetCertFromZipFile returns the native certificate bytes for signID from
// the KalkanCrypt container at zipFile. The selector must fit a non-negative C int.
func (c *Client) GetCertFromZipFile(zipFile string, flags Flag, signID int) ([]byte, error) {
	if err := validateNativeSignerID("signID", signID); err != nil {
		return nil, err
	}

	nativeFlags, err := flagsToNativeInt(flags)
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[zipContext](c, "GetCertFromZipFile")
	if err != nil {
		return nil, err
	}

	return c.callBufferWithCapacityLocked("GetCertFromZipFile", c.config.outputInitialCapacity(initialCertOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.GetCertFromZipFile(kalkancrypt.GetCertFromZipFileCall{
			ZipFile:  zipFile,
			Flags:    nativeFlags,
			SignID:   signID,
			Capacity: capacity,
		})
	})
}
