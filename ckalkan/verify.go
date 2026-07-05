package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// VerifyData calls VerifyData and returns the decoded data, verification info,
// and optionally the signer certificate selected by CertID.
func (c *Client) VerifyData(req VerifyDataRequest) (VerifyDataResult, error) {
	return c.verifyData(req, false)
}

// UVerifyData calls UVerifyData, KalkanCrypt's Unicode variant of VerifyData.
func (c *Client) UVerifyData(req VerifyDataRequest) (VerifyDataResult, error) {
	return c.verifyData(req, true)
}

func (c *Client) verifyData(req VerifyDataRequest, unicode bool) (VerifyDataResult, error) {
	if err := validateNativeSignerID("CertID", req.CertID); err != nil {
		return VerifyDataResult{}, err
	}

	nativeFlags, err := flagsToNativeInt(req.Flags)
	if err != nil {
		return VerifyDataResult{}, err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[cmsContext](c, "VerifyData")
	if err != nil {
		return VerifyDataResult{}, err
	}

	dataCap := boundedOutputCapacity(c.config.requestOutputInitialCapacity(req.DataCapacity, initialSignatureBuffer), c.config.maxBufferSize)
	infoCap := boundedOutputCapacity(c.config.requestOutputInitialCapacity(req.VerifyInfoCapacity, initialInfoOutputBuffer), c.config.maxBufferSize)
	certCap := boundedOutputCapacity(c.config.requestOutputInitialCapacity(req.CertCapacity, initialCertOutputBuffer), c.config.maxBufferSize)

	for {
		call := kalkancrypt.VerifyDataCall{
			Alias:        req.Alias,
			Flags:        nativeFlags,
			Data:         req.Data,
			Signature:    req.Signature,
			CertID:       req.CertID,
			DataCapacity: dataCap,
			InfoCapacity: infoCap,
			CertCapacity: certCap,
		}

		c.clearErrorLocked()

		var (
			result kalkancrypt.VerifyResult
			err    error
		)

		if unicode {
			result, err = ctx.UVerifyData(call)
		} else {
			result, err = ctx.VerifyData(call)
		}

		if err != nil {
			return VerifyDataResult{}, err
		}

		code := ErrorCode(result.Code)
		if shouldRetryVerifyDataOutput(code, result, dataCap, infoCap, certCap) {
			nextDataCap, dataGrown := growReportedCapacity(dataCap, result.DataLen, c.config.maxBufferSize)
			nextInfoCap, infoGrown := growReportedCapacity(infoCap, result.InfoLen, c.config.maxBufferSize)
			nextCertCap, certGrown := growReportedCapacity(certCap, result.CertLen, c.config.maxBufferSize)

			if !dataGrown && !infoGrown && !certGrown {
				return VerifyDataResult{}, c.wrapCodeLocked(retryErrorCode(code))
			}

			dataCap, infoCap, certCap = nextDataCap, nextInfoCap, nextCertCap

			continue
		}

		if err := c.wrapCodeLocked(code); err != nil {
			return VerifyDataResult{}, err
		}

		return VerifyDataResult{
			Data:       result.Data,
			VerifyInfo: string(trimCStringBytes(result.Info)),
			Cert:       result.Cert,
		}, nil
	}
}

func shouldRetryVerifyDataOutput(code ErrorCode, result kalkancrypt.VerifyResult, dataCap, infoCap, certCap int) bool {
	return code == ErrorBufferTooSmall ||
		code == ErrorOK && (result.DataLen > dataCap || result.InfoLen > infoCap || result.CertLen > certCap)
}
