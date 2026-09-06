package kalkancrypt

// GetTimeFromSig returns the native status and Unix timestamp embedded for
// the selected CMS signer. Flags describe the native input representation.
func (c *Context) GetTimeFromSig(data []byte, flags, sigID int) (uint64, int64) {
	if c.closed() {
		return errorLibraryNotInitialized, 0
	}

	return c.driver.GetTimeFromSig(data, flags, sigID)
}

// GetCertFromCMS extracts a certificate using the native signer selector.
// Linux SDK 2.0.13 expects in-memory CMS and numbers certificates from 1.
func (c *Context) GetCertFromCMS(call GetCertFromCMSCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.GetCertFromCMS(call)
}
