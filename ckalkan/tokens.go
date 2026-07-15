package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// GetTokens calls KC_GetTokens and returns the raw token list plus native count.
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

	return c.callListLocked(func(bufferSize int) (kalkancrypt.ListResult, error) {
		return ctx.GetTokens(nativeStorage, bufferSize)
	})
}

// GetCertificatesList calls KC_GetCertificatesList and returns the raw alias list
// plus native count.
//
// The native ABI does not receive the output-buffer capacity.
func (c *Client) GetCertificatesList() (ListResult, error) {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[tokenStoreContext](c, "GetCertificatesList")
	if err != nil {
		return ListResult{}, err
	}

	return c.callListLocked(func(bufferSize int) (kalkancrypt.ListResult, error) {
		return ctx.GetCertificatesList(bufferSize)
	})
}

// LoadKeyStore calls KC_LoadKeyStore. For PKCS#12 storage, container is normally
// a path to the .p12 file and password is the container password.
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
