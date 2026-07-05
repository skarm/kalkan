package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// ZipConVerify calls ZipConVerify and returns the native verification info for a
// KalkanCrypt ZIP container.
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

	out, err := c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(initialInfoOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.ZipConVerify(zipFile, nativeFlags, capacity)
	})

	return string(trimCStringBytes(out)), err
}

// ZipConSign calls ZipConSign and signs files into a KalkanCrypt ZIP container.
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

// GetCertFromZipFile calls KC_getCertFromZipFile and extracts a signer
// certificate from a KalkanCrypt ZIP container.
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

	return c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(initialCertOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.GetCertFromZipFile(zipFile, nativeFlags, signID, capacity)
	})
}
