package kalkancrypt

// GetTokens calls KC_GetTokens.
func (c *Context) GetTokens(storage uint64, capacity int) (ListResult, error) {
	if c.closed() {
		return ListResult{}, ErrClosed
	}

	return c.driver.GetTokens(storage, capacity)
}

// GetCertificatesList calls KC_GetCertificatesList.
func (c *Context) GetCertificatesList(capacity int) (ListResult, error) {
	if c.closed() {
		return ListResult{}, ErrClosed
	}

	return c.driver.GetCertificatesList(capacity)
}

// LoadKeyStore calls KC_LoadKeyStore.
func (c *Context) LoadKeyStore(storage int, password, container, alias string) uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.LoadKeyStore(storage, password, container, alias)
}
