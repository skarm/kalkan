package kalkancrypt

// VerifyXML verifies in-memory XML and returns the native diagnostic output
// and status from one attempt.
func (c *Context) VerifyXML(call VerifyXMLCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.VerifyXML(call)
}

// GetCertFromXML extracts the certificate selected by the native signID
// parameter from xml using capacity bytes of output storage.
func (c *Context) GetCertFromXML(xml []byte, signID, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.GetCertFromXML(xml, signID, capacity)
}

// GetSigAlgFromXML retrieves the native signature algorithm identifier from
// xml using capacity bytes of output storage.
func (c *Context) GetSigAlgFromXML(xml []byte, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.GetSigAlgFromXML(xml, capacity)
}
