package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// SignXML calls SignXML and returns the signed XML bytes produced by KalkanCrypt.
func (c *Client) SignXML(req SignXMLRequest) ([]byte, error) {
	nativeFlags, err := flagsToNativeInt(req.Flags)
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[xmlContext](c, "SignXML")
	if err != nil {
		return nil, err
	}

	initial := c.config.requestOutputInitialCapacity(req.OutputCapacity, initialSignatureBuffer)

	return c.callBufferWithCapacityLocked(initial, func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.SignXML(kalkancrypt.SignXMLCall{
			Alias:           req.Alias,
			Flags:           nativeFlags,
			XML:             req.XML,
			SignNodeID:      req.SignNodeID,
			ParentSignNode:  req.ParentSignNode,
			ParentNamespace: req.ParentNamespace,
			Capacity:        capacity,
		})
	})
}

// VerifyXML calls VerifyXML and returns the native verification info string.
func (c *Client) VerifyXML(alias string, flags Flag, xml []byte) (string, error) {
	nativeFlags, err := flagsToNativeInt(flags)
	if err != nil {
		return "", err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[xmlContext](c, "VerifyXML")
	if err != nil {
		return "", err
	}

	out, err := c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(initialInfoOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.VerifyXML(alias, nativeFlags, xml, capacity)
	})

	return string(trimCStringBytes(out)), err
}

// GetCertFromXML calls KC_getCertFromXML and extracts a signer certificate from XML.
func (c *Client) GetCertFromXML(xml []byte, signID int) ([]byte, error) {
	if err := validateNativeSignerID("signID", signID); err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[xmlContext](c, "GetCertFromXML")
	if err != nil {
		return nil, err
	}

	return c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(initialCertOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.GetCertFromXML(xml, signID, capacity)
	})
}

// GetSigAlgFromXML calls KC_getSigAlgFromXML and returns the XML signature algorithm.
func (c *Client) GetSigAlgFromXML(xml []byte) (string, error) {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[xmlContext](c, "GetSigAlgFromXML")
	if err != nil {
		return "", err
	}

	out, err := c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(initialInfoOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.GetSigAlgFromXML(xml, capacity)
	})

	return string(trimCStringBytes(out)), err
}
