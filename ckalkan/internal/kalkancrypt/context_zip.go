package kalkancrypt

// ZipConVerify verifies the container at zipFile and returns native
// diagnostics using capacity bytes of output storage.
func (c *Context) ZipConVerify(zipFile string, flags, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.ZipConVerify(zipFile, flags, capacity)
}

// ZipConSign signs call.FilePath into a container in call.OutDir using the
// native container name and flags, and returns the native status.
func (c *Context) ZipConSign(call ZipConSignCall) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.ZipConSign(call)
}

// GetCertFromZipFile extracts the selected signer certificate from a ZIP
// container using call.Capacity bytes of output storage.
func (c *Context) GetCertFromZipFile(call GetCertFromZipFileCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.GetCertFromZipFile(call)
}
