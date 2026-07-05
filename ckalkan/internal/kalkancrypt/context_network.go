package kalkancrypt

// SetTSAURL calls KC_TSASetUrl.
func (c *Context) SetTSAURL(tsaURL string) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.SetTSAURL(tsaURL)
}

// SetProxy calls KC_SetProxy.
func (c *Context) SetProxy(call ProxyCall) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.SetProxy(call)
}
