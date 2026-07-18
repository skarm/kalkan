package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// VerifyData calls VerifyData and returns decoded embedded data when the native
// verification mode produces it, verification info, and optionally the signer
// certificate selected by CertID.
func (c *Client) VerifyData(req VerifyDataRequest) (VerifyDataResult, error) {
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

	outputPolicy := platformVerifyDataOutputPolicy(req)

	capacities := verifyDataCapacities{
		data: 1,
		info: boundedOutputCapacity(
			c.config.requestOutputInitialCapacity(req.VerifyInfoCapacity, initialInfoOutputBuffer),
			c.config.maxBufferSize,
		),
		cert: boundedOutputCapacity(
			c.config.requestOutputInitialCapacity(req.CertCapacity, initialCertOutputBuffer),
			c.config.maxBufferSize,
		),
	}
	if outputPolicy.dataBufferActive {
		capacities.data = boundedOutputCapacity(
			c.config.requestOutputInitialCapacity(req.DataCapacity, initialSignatureBuffer),
			c.config.maxBufferSize,
		)
	}

	for {
		call := kalkancrypt.VerifyDataCall{
			Alias:        req.Alias,
			Flags:        nativeFlags,
			Data:         req.Data,
			Signature:    req.Signature,
			CertID:       req.CertID,
			DataCapacity: capacities.data,
			InfoCapacity: capacities.info,
			CertCapacity: capacities.cert,
		}

		c.clearErrorLocked()

		result, err := ctx.VerifyData(call)
		if err != nil {
			return VerifyDataResult{}, err
		}

		if err := validateVerifyDataOutputLengths(result, outputPolicy); err != nil {
			return VerifyDataResult{}, err
		}

		code := ErrorCode(result.Code)
		if shouldRetryVerifyDataOutput(code, result, capacities, outputPolicy) {
			capacities, err = nextVerifyDataCapacities(
				code,
				result,
				capacities,
				outputPolicy,
				c.config.maxBufferSize,
			)
			if err != nil {
				return VerifyDataResult{}, err
			}

			continue
		}

		if err := c.wrapCodeLocked(code); err != nil {
			return VerifyDataResult{}, err
		}

		if outputPolicy.dataBufferActive {
			if err := validateNativeOutputDataLength("VerifyData data", result.Data, result.DataLen); err != nil {
				return VerifyDataResult{}, err
			}
		}

		for _, output := range []struct {
			name   string
			data   []byte
			length int
		}{
			{name: "VerifyData info", data: result.Info, length: result.InfoLen},
			{name: "VerifyData certificate", data: result.Cert, length: result.CertLen},
		} {
			if err := validateNativeOutputDataLength(output.name, output.data, output.length); err != nil {
				return VerifyDataResult{}, err
			}
		}

		data := result.Data
		if !outputPolicy.returnDecodedData {
			data = nil
		}

		return VerifyDataResult{
			Data:       capacityLimitedBytes(data),
			VerifyInfo: string(bytesBeforeNULTerminator(result.Info)),
			Cert:       capacityLimitedBytes(result.Cert),
		}, nil
	}
}

func validateVerifyDataOutputLengths(result kalkancrypt.VerifyResult, policy verifyDataOutputPolicy) error {
	if policy.dataBufferActive && result.DataLen < 0 {
		return invalidNativeOutputLength("VerifyData data", result.DataLen)
	}

	for _, output := range []struct {
		name   string
		length int
	}{
		{name: "VerifyData info", length: result.InfoLen},
		{name: "VerifyData certificate", length: result.CertLen},
	} {
		if output.length < 0 {
			return invalidNativeOutputLength(output.name, output.length)
		}
	}

	return nil
}

type verifyDataOutputPolicy struct {
	dataBufferActive   bool
	returnDecodedData  bool
	retrySaturatedData bool
	dataCapacityHint   int
}

type verifyDataCapacities struct {
	data int
	info int
	cert int
}

func shouldRetryVerifyDataOutput(code ErrorCode, result kalkancrypt.VerifyResult, capacities verifyDataCapacities, policy verifyDataOutputPolicy) bool {
	// KalkanCrypt can truncate attached data, return KCR_OK, and set
	// DataLen to the supplied capacity instead of the required length. Treat a
	// saturated data buffer as ambiguous only where the platform policy confirms
	// that data is an actual output.
	if code == ErrorBufferTooSmall {
		return true
	}

	if code != ErrorOK {
		return false
	}

	dataNeedsRetry := policy.dataBufferActive && (result.DataLen > capacities.data ||
		policy.retrySaturatedData && result.DataLen == capacities.data)

	return dataNeedsRetry || result.InfoLen > capacities.info || result.CertLen > capacities.cert
}

func nextVerifyDataCapacities(
	code ErrorCode,
	result kalkancrypt.VerifyResult,
	current verifyDataCapacities,
	policy verifyDataOutputPolicy,
	hardMaximum int,
) (verifyDataCapacities, error) {
	next, err := nextOutputBufferCapacities(
		code,
		hardMaximum,
		outputBufferState{
			current:        current.data,
			reported:       result.DataLen,
			active:         policy.dataBufferActive,
			retrySaturated: policy.retrySaturatedData,
			growthHint:     policy.dataCapacityHint,
		},
		outputBufferState{current: current.info, reported: result.InfoLen, active: true},
		outputBufferState{current: current.cert, reported: result.CertLen, active: true},
	)
	if err != nil {
		return verifyDataCapacities{}, err
	}

	return verifyDataCapacities{data: next[0], info: next[1], cert: next[2]}, nil
}

func verifyDataReturnsDecodedData(req VerifyDataRequest) bool {
	return req.Flags&SignCMS != 0 &&
		req.Flags&DetachedData == 0 &&
		req.Flags&InFile == 0
}
