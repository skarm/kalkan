package kalkancrypt

// GetTimeFromSig calls KC_GetTimeFromSig.
func (c *Context) GetTimeFromSig(data []byte, flags, sigID int) (uint64, int64) {
	if c.closed() {
		return errorLibraryNotInitialized, 0
	}

	return c.driver.GetTimeFromSig(data, flags, sigID)
}

// GetCertFromCMS calls KC_GetCertFromCMS.
func (c *Context) GetCertFromCMS(cms []byte, signID, flags, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.GetCertFromCMS(cms, signID, flags, capacity)
}
