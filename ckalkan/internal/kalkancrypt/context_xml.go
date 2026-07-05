package kalkancrypt

// VerifyXML calls VerifyXML.
func (c *Context) VerifyXML(alias string, flags int, xml []byte, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.VerifyXML(alias, flags, xml, capacity)
}

// GetCertFromXML calls KC_getCertFromXML.
func (c *Context) GetCertFromXML(xml []byte, signID, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.GetCertFromXML(xml, signID, capacity)
}

// GetSigAlgFromXML calls KC_getSigAlgFromXML.
func (c *Context) GetSigAlgFromXML(xml []byte, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.GetSigAlgFromXML(xml, capacity)
}
