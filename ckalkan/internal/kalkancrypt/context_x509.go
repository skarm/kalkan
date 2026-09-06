package kalkancrypt

// X509LoadCertificateFromFile loads certPath into the native store selected
// by certType and returns the native status.
func (c *Context) X509LoadCertificateFromFile(certPath string, certType int) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.X509LoadCertificateFromFile(certPath, certType)
}

// X509LoadCertificateFromBuffer loads certificate bytes in format and
// returns the native status. The buffer API has no certificate-role parameter.
func (c *Context) X509LoadCertificateFromBuffer(cert []byte, format int) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.X509LoadCertificateFromBuffer(cert, format)
}

// X509ExportCertificateFromStore exports the certificate for alias in the
// requested format using capacity bytes of output storage.
func (c *Context) X509ExportCertificateFromStore(alias string, format, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.X509ExportCertificateFromStore(alias, format, capacity)
}

// X509CertificateGetInfo retrieves native property prop from cert using
// capacity bytes of output storage.
func (c *Context) X509CertificateGetInfo(cert []byte, prop, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.X509CertificateGetInfo(cert, prop, capacity)
}

// X509ValidateCertificate validates a certificate using the requested
// revocation settings and returns separate diagnostic and OCSP outputs.
func (c *Context) X509ValidateCertificate(call ValidateCertificateCall) (ValidateResult, error) {
	if c.closed() {
		return ValidateResult{}, ErrClosed
	}

	return c.driver.X509ValidateCertificate(call)
}
