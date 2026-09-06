package ckalkan

import (
	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
	"github.com/skarm/kalkan/internal/nativebytes"
)

// X509LoadCertificateFromFile adds a CA, intermediate, or user certificate
// from certPath to the native store selected by certType.
func (c *Client) X509LoadCertificateFromFile(certPath string, certType CertType) error {
	nativeType, err := enumToNativeInt("certificate type", int(certType))
	if err != nil {
		return err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[x509Context](c, "X509LoadCertificateFromFile")
	if err != nil {
		return err
	}

	c.clearErrorLocked()

	return c.wrapCodeLocked(ErrorCode(ctx.X509LoadCertificateFromFile(certPath, nativeType)))
}

// X509LoadCertificateFromBuffer loads certificate bytes in format into the
// native store. This native API does not accept a certificate-role parameter.
func (c *Client) X509LoadCertificateFromBuffer(cert []byte, format CertFormat) error {
	nativeFormat, err := enumToNativeInt("certificate format", int(format))
	if err != nil {
		return err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[x509Context](c, "X509LoadCertificateFromBuffer")
	if err != nil {
		return err
	}

	c.clearErrorLocked()

	return c.wrapCodeLocked(ErrorCode(ctx.X509LoadCertificateFromBuffer(cert, nativeFormat)))
}

// X509ExportCertificateFromStore returns the stored certificate for alias
// in the requested format.
func (c *Client) X509ExportCertificateFromStore(alias string, format CertFormat) ([]byte, error) {
	nativeFormat, err := enumToNativeInt("certificate format", int(format))
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[x509Context](c, "X509ExportCertificateFromStore")
	if err != nil {
		return nil, err
	}

	return c.callBufferWithCapacityLocked("X509ExportCertificateFromStore", c.config.outputInitialCapacity(initialCertOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.X509ExportCertificateFromStore(alias, nativeFormat, capacity)
	})
}

// X509CertificateGetInfo returns native property prop from cert as text
// bytes, excluding the NUL terminator and any trailing buffer padding.
func (c *Client) X509CertificateGetInfo(cert []byte, prop CertProp) ([]byte, error) {
	nativeProperty, err := enumToNativeInt("certificate property", int(prop))
	if err != nil {
		return nil, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[x509Context](c, "X509CertificateGetInfo")
	if err != nil {
		return nil, err
	}

	out, err := c.callBufferWithCapacityLocked("X509CertificateGetInfo", c.config.outputInitialCapacity(initialInfoOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.X509CertificateGetInfo(cert, nativeProperty, capacity)
	})
	if err != nil {
		return nil, err
	}

	return nativebytes.BeforeNUL(out), nil
}

// X509ValidateCertificate checks a certificate using the requested validation
// mode and returns native diagnostics. OCSPResponse is populated only when
// req.Flags includes [GetOCSPResponse].
func (c *Client) X509ValidateCertificate(req ValidateCertificateRequest) (ValidateCertificateResult, error) {
	nativeType, err := enumToNativeInt("validation type", int(req.ValidationType))
	if err != nil {
		return ValidateCertificateResult{}, err
	}

	nativeFlags, err := flagsToNativeInt(req.Flags)
	if err != nil {
		return ValidateCertificateResult{}, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[x509Context](c, "X509ValidateCertificate")
	if err != nil {
		return ValidateCertificateResult{}, err
	}

	infoCap := boundedOutputCapacity(c.config.requestOutputInitialCapacity(req.OutputCapacity, initialInfoOutputBuffer), c.config.maxBufferSize)
	// Keep a valid native OCSP buffer even when it is inactive. SDK 2.0.13 can
	// leave its in/out length unchanged, so only consume it when requested.
	ocspCap := boundedOutputCapacity(c.config.requestOutputInitialCapacity(req.OCSPCapacity, initialCertOutputBuffer), c.config.maxBufferSize)
	returnOCSP := req.Flags&GetOCSPResponse != 0

	for {
		c.clearErrorLocked()

		result, err := ctx.X509ValidateCertificate(kalkancrypt.ValidateCertificateCall{
			Certificate:    req.Certificate,
			ValidationType: nativeType,
			ValidationPath: req.ValidationPath,
			CheckTimeUnix:  req.CheckTimeUnix,
			Flags:          nativeFlags,
			InfoCapacity:   infoCap,
			OCSPCapacity:   ocspCap,
		})
		if err != nil {
			return ValidateCertificateResult{}, err
		}

		if result.InfoLen < 0 {
			return ValidateCertificateResult{}, invalidNativeOutputLength("certificate-validation info", result.InfoLen)
		}

		if returnOCSP && result.OCSPLen < 0 {
			return ValidateCertificateResult{}, invalidNativeOutputLength("OCSP response", result.OCSPLen)
		}

		code := ErrorCode(result.Code)
		if shouldRetryValidateCertificateOutput(code, result, infoCap, ocspCap, returnOCSP) {
			next, err := nextOutputBufferCapacities(
				"X509ValidateCertificate",
				code,
				c.config.maxBufferSize,
				outputBufferState{current: infoCap, reported: result.InfoLen, active: true},
				outputBufferState{current: ocspCap, reported: result.OCSPLen, active: returnOCSP},
			)
			if err != nil {
				return ValidateCertificateResult{}, err
			}

			infoCap, ocspCap = next[0], next[1]

			continue
		}

		if err := c.wrapCodeLocked(code); err != nil {
			return ValidateCertificateResult{}, err
		}

		if err := validateNativeOutputDataLength("certificate-validation info", result.Info, result.InfoLen); err != nil {
			return ValidateCertificateResult{}, err
		}

		var ocspResponse []byte

		if returnOCSP {
			if err := validateNativeOutputDataLength("OCSP response", result.OCSP, result.OCSPLen); err != nil {
				return ValidateCertificateResult{}, err
			}

			ocspResponse = capacityLimitedBytes(result.OCSP)
		}

		return ValidateCertificateResult{
			Info:         string(nativebytes.BeforeNUL(result.Info)),
			OCSPResponse: ocspResponse,
		}, nil
	}
}

func shouldRetryValidateCertificateOutput(code ErrorCode, result kalkancrypt.ValidateResult, infoCap, ocspCap int, returnOCSP bool) bool {
	return code == ErrorBufferTooSmall ||
		code == ErrorOK && (result.InfoLen > infoCap || returnOCSP && result.OCSPLen > ocspCap)
}
