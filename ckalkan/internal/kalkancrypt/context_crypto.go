package kalkancrypt

// HashData calls HashData.
func (c *Context) HashData(call HashDataCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.HashData(call)
}

// SignHash calls SignHash.
func (c *Context) SignHash(call SignHashCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.SignHash(call)
}

// SignData calls SignData.
func (c *Context) SignData(call SignDataCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.SignData(call)
}

// SignXML calls SignXML.
func (c *Context) SignXML(call SignXMLCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.SignXML(call)
}

// SignWSSE calls SignWSSE.
func (c *Context) SignWSSE(call SignWSSECall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.SignWSSE(call)
}

// VerifyData calls VerifyData.
func (c *Context) VerifyData(call VerifyDataCall) (VerifyResult, error) {
	if c.closed() {
		return VerifyResult{}, ErrClosed
	}

	return c.driver.VerifyData(call)
}

// UVerifyData calls the universal file verifier found in the verified Linux SDK.
// Signature in the call is a file path; the native function reads it and
// auto-detects XML, ZIP, draft, or CMS input. This low-level method is retained
// for ABI coverage.
func (c *Context) UVerifyData(call VerifyDataCall) (VerifyResult, error) {
	if c.closed() {
		return VerifyResult{}, ErrClosed
	}

	return c.driver.UVerifyData(call)
}
