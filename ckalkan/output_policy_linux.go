//go:build linux

package ckalkan

func platformVerifyDataOutputPolicy(req VerifyDataRequest) verifyDataOutputPolicy {
	returnsDecodedData := verifyDataReturnsDecodedData(req)
	policy := verifyDataOutputPolicy{
		dataBufferActive:   returnsDecodedData,
		returnDecodedData:  returnsDecodedData,
		retrySaturatedData: returnsDecodedData,
	}

	if policy.dataBufferActive {
		// The encoded attached CMS size is a useful payload estimate and normally
		// exceeds the embedded data size. Use it after the first ambiguous
		// saturation instead of repeatedly doubling or allocating a CMS-sized
		// buffer eagerly; further saturation retries remain the fallback.
		policy.dataCapacityHint = len(req.Signature)
	}

	return policy
}

func platformZIPVerifySafetyCapacity() int {
	return initialZIPVerifyBuffer
}
