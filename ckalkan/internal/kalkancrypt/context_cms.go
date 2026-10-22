package kalkancrypt

// GetTimeFromSig returns the status and Unix timestamp for signer sigID in CMS
// data with flags.
func (c *Context) GetTimeFromSig(data []byte, flags, sigID int) (uint64, int64) {
	if c.closed() {
		return errorLibraryNotInitialized, 0
	}

	return c.driver.GetTimeFromSig(data, flags, sigID)
}

// GetCertFromCMS returns the certificate selected by call.SignID from call.CMS
// and its native status.
// The Linux SDK expects in-memory CMS and numbers certificates from 1.
func (c *Context) GetCertFromCMS(call GetCertFromCMSCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.GetCertFromCMS(call)
}
