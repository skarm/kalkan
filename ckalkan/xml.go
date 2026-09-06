package ckalkan

import (
	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
	"github.com/skarm/kalkan/internal/nativebytes"
)

// SignXML returns req.XML with a native signature inserted using the requested
// node selectors and flags. The input must contain XML bytes, not a file path.
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

	initial := c.config.signedXMLOutputInitialCapacity(req.OutputCapacity, req.XML)

	out, err := c.callBufferWithCapacityLocked("SignXML", initial, func(capacity int) (kalkancrypt.BufferResult, error) {
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
	if err != nil {
		return nil, err
	}

	return nativebytes.BeforeNUL(out), nil
}

// VerifyXML verifies in-memory XML using the native flags and returns the
// verification diagnostic text. A nonzero native status returns an error.
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

	out, err := c.callBufferWithCapacityLocked("VerifyXML", c.config.outputInitialCapacity(initialInfoOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.VerifyXML(kalkancrypt.VerifyXMLCall{
			Alias:    alias,
			Flags:    nativeFlags,
			XML:      xml,
			Capacity: capacity,
		})
	})
	if err != nil {
		return "", err
	}

	return string(nativebytes.BeforeNUL(out)), nil
}

// GetCertFromXML returns the signer certificate selected by signID from XML.
// Linux SDK 2.0.13 accepts one-based signature positions and also matches numeric
// Signature Id attributes; 0 aliases the first signature. Colliding Id values
// can select an earlier signature. ErrorIDAttrNotFound signals no match.
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

	return c.callBufferWithCapacityLocked("GetCertFromXML", c.config.outputInitialCapacity(initialCertOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.GetCertFromXML(xml, signID, capacity)
	})
}

// GetSigAlgFromXML returns the native signature algorithm identifier from
// in-memory XML, excluding its NUL terminator.
func (c *Client) GetSigAlgFromXML(xml []byte) (string, error) {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[xmlContext](c, "GetSigAlgFromXML")
	if err != nil {
		return "", err
	}

	out, err := c.callBufferWithCapacityLocked("GetSigAlgFromXML", c.config.outputInitialCapacity(initialInfoOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.GetSigAlgFromXML(xml, capacity)
	})
	if err != nil {
		return "", err
	}

	return string(nativebytes.BeforeNUL(out)), nil
}
