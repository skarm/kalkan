package kalkancrypt

// GetTokens calls KC_GetTokens.
func (c *Context) GetTokens(storage uint64, bufferSize int) (ListResult, error) {
	if c.closed() {
		return ListResult{}, ErrClosed
	}

	return c.driver.GetTokens(storage, bufferSize)
}

// GetCertificatesList calls KC_GetCertificatesList.
func (c *Context) GetCertificatesList(bufferSize int) (ListResult, error) {
	if c.closed() {
		return ListResult{}, ErrClosed
	}

	return c.driver.GetCertificatesList(bufferSize)
}

// LoadKeyStore calls KC_LoadKeyStore.
func (c *Context) LoadKeyStore(storage int, password, container, alias string) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.LoadKeyStore(storage, password, container, alias)
}
