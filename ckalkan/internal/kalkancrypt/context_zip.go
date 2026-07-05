package kalkancrypt

// ZipConVerify calls ZipConVerify.
func (c *Context) ZipConVerify(zipFile string, flags, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.ZipConVerify(zipFile, flags, capacity)
}

// ZipConSign calls ZipConSign.
func (c *Context) ZipConSign(call ZipConSignCall) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.ZipConSign(call)
}

// GetCertFromZipFile calls KC_getCertFromZipFile.
func (c *Context) GetCertFromZipFile(zipFile string, flags, signID, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.GetCertFromZipFile(zipFile, flags, signID, capacity)
}
