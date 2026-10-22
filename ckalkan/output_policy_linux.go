//go:build linux

package ckalkan

func platformCMSLastError(ctx cmsContext) ErrorCode {
	return ErrorCode(ctx.LastError())
}

func platformVerifyDataOutputPolicy(req VerifyDataRequest) verifyDataOutputPolicy {
	returnsDecodedData := verifyDataReturnsDecodedData(req)
	policy := verifyDataOutputPolicy{
		dataBufferActive:   returnsDecodedData,
		returnDecodedData:  returnsDecodedData,
		retrySaturatedData: returnsDecodedData,
	}

	if policy.dataBufferActive {
		// The encoded attached CMS size normally exceeds the embedded payload size.
		// Use that size as a capacity hint after the first ambiguous saturation.
		// Later retries still use geometric growth.
		policy.dataCapacityHint = len(req.Signature)
	}

	return policy
}

func platformZIPVerifySafetyCapacity() int {
	return initialZIPVerifyBuffer
}
