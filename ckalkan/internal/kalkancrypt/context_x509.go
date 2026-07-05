package kalkancrypt

// X509LoadCertificateFromFile calls X509LoadCertificateFromFile.
func (c *Context) X509LoadCertificateFromFile(certPath string, certType int) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.X509LoadCertificateFromFile(certPath, certType)
}

// X509LoadCertificateFromBuffer calls X509LoadCertificateFromBuffer.
func (c *Context) X509LoadCertificateFromBuffer(cert []byte, format int) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.X509LoadCertificateFromBuffer(cert, format)
}

// X509ExportCertificateFromStore calls X509ExportCertificateFromStore.
func (c *Context) X509ExportCertificateFromStore(alias string, format, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.X509ExportCertificateFromStore(alias, format, capacity)
}

// X509CertificateGetInfo calls X509CertificateGetInfo.
func (c *Context) X509CertificateGetInfo(cert []byte, prop, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.X509CertificateGetInfo(cert, prop, capacity)
}

// X509ValidateCertificate calls X509ValidateCertificate.
func (c *Context) X509ValidateCertificate(call ValidateCertificateCall) (ValidateResult, error) {
	if c.closed() {
		return ValidateResult{}, ErrClosed
	}

	return c.driver.X509ValidateCertificate(call)
}
