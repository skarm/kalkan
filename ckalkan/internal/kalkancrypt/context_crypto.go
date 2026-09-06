package kalkancrypt

// HashData computes a digest using call.Algorithm and call.Flags, with one
// native attempt using call.Capacity bytes of output storage.
func (c *Context) HashData(call HashDataCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.HashData(call)
}

// SignHash signs the precomputed digest with the loaded key selected by
// call.Alias and returns the native signature output.
func (c *Context) SignHash(call SignHashCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.SignHash(call)
}

// SignData signs data or extends an existing signature according to call.Flags.
// It returns the output from one native attempt.
func (c *Context) SignData(call SignDataCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.SignData(call)
}

// SignXML signs in-memory XML using the requested node selectors and flags.
// It returns the signed document from one native attempt.
func (c *Context) SignXML(call SignXMLCall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.SignXML(call)
}

// SignWSSE creates a WS-Security signature for the selected XML node and
// returns the signed document from one native attempt.
func (c *Context) SignWSSE(call SignWSSECall) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.SignWSSE(call)
}

// VerifyData verifies a signature and returns the native status, decoded
// data, verification diagnostics, and selected signer certificate.
func (c *Context) VerifyData(call VerifyDataCall) (VerifyResult, error) {
	if c.closed() {
		return VerifyResult{}, ErrClosed
	}

	return c.driver.VerifyData(call)
}

// UVerifyData invokes the native universal file verifier. In Linux SDK
// 2.0.13, call.Signature is a file path and the SDK detects XML, ZIP, draft, or
// CMS input. Outputs retain their native status and reported lengths.
func (c *Context) UVerifyData(call VerifyDataCall) (VerifyResult, error) {
	if c.closed() {
		return VerifyResult{}, ErrClosed
	}

	return c.driver.UVerifyData(call)
}
