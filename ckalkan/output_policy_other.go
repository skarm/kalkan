//go:build !linux

package ckalkan

func platformVerifyDataOutputPolicy(req VerifyDataRequest) verifyDataOutputPolicy {
	// These platforms allocate a data buffer for every verification mode but
	// return its contents only for attached in-memory CMS. Exact saturation
	// does not trigger a retry without confirmed native truncation behavior.
	return verifyDataOutputPolicy{
		dataBufferActive:  true,
		returnDecodedData: verifyDataReturnsDecodedData(req),
	}
}

func platformZIPVerifySafetyCapacity() int {
	return 0
}
