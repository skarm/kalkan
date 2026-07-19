//go:build !linux

package ckalkan

func platformVerifyDataOutputPolicy(req VerifyDataRequest) verifyDataOutputPolicy {
	// Only the public meaning of decoded data is platform-independent. Preserve
	// the established native buffer allocation and growth on platforms whose ABI
	// behavior has not been observed; the extra saturation retry remains Linux-only.
	return verifyDataOutputPolicy{
		dataBufferActive:  true,
		returnDecodedData: verifyDataReturnsDecodedData(req),
	}
}

func platformZIPVerifySafetyCapacity() int {
	return 0
}
