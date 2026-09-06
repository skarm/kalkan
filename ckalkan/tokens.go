package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// GetTokens returns the raw token list and native item count for storage.
//
// The native ABI does not receive the output-buffer capacity.
func (c *Client) GetTokens(storage Store) (ListResult, error) {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[tokenStoreContext](c, "GetTokens")
	if err != nil {
		return ListResult{}, err
	}

	nativeStorage, err := storeToNativeUnsignedLong(storage)
	if err != nil {
		return ListResult{}, err
	}

	return c.callListLocked("GetTokens", func(bufferSize int) (kalkancrypt.ListResult, error) {
		return ctx.GetTokens(nativeStorage, bufferSize)
	})
}

// GetCertificatesList returns the raw certificate alias list and native count.
//
// The native ABI does not receive the output-buffer capacity.
func (c *Client) GetCertificatesList() (ListResult, error) {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[tokenStoreContext](c, "GetCertificatesList")
	if err != nil {
		return ListResult{}, err
	}

	return c.callListLocked("GetCertificatesList", func(bufferSize int) (kalkancrypt.ListResult, error) {
		return ctx.GetCertificatesList(bufferSize)
	})
}

// LoadKeyStore loads the key container selected by storage and alias. For
// PKCS#12 storage, container is the file path and password unlocks the container.
func (c *Client) LoadKeyStore(storage Store, password, container, alias string) error {
	nativeStorage, err := storeToNativeInt(storage)
	if err != nil {
		return err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[tokenStoreContext](c, "LoadKeyStore")
	if err != nil {
		return err
	}

	c.clearErrorLocked()

	return c.wrapCodeLocked(ErrorCode(ctx.LoadKeyStore(nativeStorage, password, container, alias)))
}
