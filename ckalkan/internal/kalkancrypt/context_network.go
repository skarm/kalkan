package kalkancrypt

// SetTSAURL configures the timestamp authority endpoint for native signatures.
// It returns a wrapper status because the native function returns no status.
func (c *Context) SetTSAURL(tsaURL string) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.SetTSAURL(tsaURL)
}

// SetProxy configures the native HTTP proxy using the supplied flags and
// connection parameters, and returns the native status.
func (c *Context) SetProxy(call ProxyCall) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.SetProxy(call)
}
