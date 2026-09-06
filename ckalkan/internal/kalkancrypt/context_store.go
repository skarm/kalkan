package kalkancrypt

// GetTokens returns the raw token list and native count for storage.
// The SDK receives no buffer capacity; bufferSize controls only Go allocation.
func (c *Context) GetTokens(storage uint64, bufferSize int) (ListResult, error) {
	if c.closed() {
		return ListResult{}, ErrClosed
	}

	return c.driver.GetTokens(storage, bufferSize)
}

// GetCertificatesList returns the raw certificate list and native count.
// The SDK receives no buffer capacity; bufferSize controls only Go allocation.
func (c *Context) GetCertificatesList(bufferSize int) (ListResult, error) {
	if c.closed() {
		return ListResult{}, ErrClosed
	}

	return c.driver.GetCertificatesList(bufferSize)
}

// LoadKeyStore loads the key container for storage using password and alias,
// and returns the native status.
func (c *Context) LoadKeyStore(storage int, password, container, alias string) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.LoadKeyStore(storage, password, container, alias)
}
