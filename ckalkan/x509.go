package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// X509LoadCertificateFromFile calls X509LoadCertificateFromFile and adds a CA,
// intermediate, or user certificate from disk to the native store.
func (c *Client) X509LoadCertificateFromFile(certPath string, certType CertType) error {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[x509Context](c, "X509LoadCertificateFromFile")
	if err != nil {
		return err
	}

	c.clearErrorLocked()

	return c.wrapCodeLocked(ErrorCode(ctx.X509LoadCertificateFromFile(certPath, int(certType))))
}

// X509LoadCertificateFromBuffer calls X509LoadCertificateFromBuffer and loads a
// certificate from bytes already held by Go code.
func (c *Client) X509LoadCertificateFromBuffer(cert []byte, format CertFormat) error {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[x509Context](c, "X509LoadCertificateFromBuffer")
	if err != nil {
		return err
	}

	c.clearErrorLocked()

	return c.wrapCodeLocked(ErrorCode(ctx.X509LoadCertificateFromBuffer(cert, int(format))))
}

// X509ExportCertificateFromStore calls X509ExportCertificateFromStore and returns
// the certificate for alias in the requested format.
func (c *Client) X509ExportCertificateFromStore(alias string, format CertFormat) ([]byte, error) {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[x509Context](c, "X509ExportCertificateFromStore")
	if err != nil {
		return nil, err
	}

	return c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(initialCertOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.X509ExportCertificateFromStore(alias, int(format), capacity)
	})
}

// X509CertificateGetInfo calls X509CertificateGetInfo and returns the requested
// textual certificate property up to its native NUL terminator.
func (c *Client) X509CertificateGetInfo(cert []byte, prop CertProp) ([]byte, error) {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[x509Context](c, "X509CertificateGetInfo")
	if err != nil {
		return nil, err
	}

	out, err := c.callBufferWithCapacityLocked(c.config.outputInitialCapacity(initialInfoOutputBuffer), func(capacity int) (kalkancrypt.BufferResult, error) {
		return ctx.X509CertificateGetInfo(cert, int(prop), capacity)
	})
	if err != nil {
		return nil, err
	}

	return bytesBeforeNULTerminator(out), nil
}

// X509ValidateCertificate calls KalkanCrypt and returns validation information
// and an optional OCSP response.
func (c *Client) X509ValidateCertificate(req ValidateCertificateRequest) (ValidateCertificateResult, error) {
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
	ocspCap := boundedOutputCapacity(c.config.requestOutputInitialCapacity(req.OCSPCapacity, initialCertOutputBuffer), c.config.maxBufferSize)

	for {
		c.clearErrorLocked()

		result, err := ctx.X509ValidateCertificate(kalkancrypt.ValidateCertificateCall{
			Certificate:    req.Certificate,
			ValidationType: int(req.ValidationType),
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

		if result.OCSPLen < 0 {
			return ValidateCertificateResult{}, invalidNativeOutputLength("OCSP response", result.OCSPLen)
		}

		code := ErrorCode(result.Code)
		if shouldRetryValidateCertificateOutput(code, result, infoCap, ocspCap) {
			next, err := nextOutputBufferCapacities(
				code,
				c.config.maxBufferSize,
				outputBufferState{current: infoCap, reported: result.InfoLen, active: true},
				outputBufferState{current: ocspCap, reported: result.OCSPLen, active: true},
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

		if err := validateNativeOutputDataLength("OCSP response", result.OCSP, result.OCSPLen); err != nil {
			return ValidateCertificateResult{}, err
		}

		return ValidateCertificateResult{
			Info:         string(bytesBeforeNULTerminator(result.Info)),
			OCSPResponse: capacityLimitedBytes(result.OCSP),
		}, nil
	}
}

func shouldRetryValidateCertificateOutput(code ErrorCode, result kalkancrypt.ValidateResult, infoCap, ocspCap int) bool {
	return code == ErrorBufferTooSmall ||
		code == ErrorOK && (result.InfoLen > infoCap || result.OCSPLen > ocspCap)
}
