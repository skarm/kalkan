package kalkancrypt

// HashData calls HashData.
func (c *Context) HashData(algorithm string, flags int, data []byte, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.HashData(algorithm, flags, data, capacity)
}

// SignHash calls SignHash.
func (c *Context) SignHash(alias string, flags int, hash []byte, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.SignHash(alias, flags, hash, capacity)
}

// SignData calls SignData.
func (c *Context) SignData(alias string, flags int, data, signature []byte, capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.SignData(alias, flags, data, signature, capacity)
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

// UVerifyData calls UVerifyData.
func (c *Context) UVerifyData(call VerifyDataCall) (VerifyResult, error) {
	if c.closed() {
		return VerifyResult{}, ErrClosed
	}

	return c.driver.UVerifyData(call)
}
