package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// GetTokens calls KC_GetTokens and returns the raw token list plus native count.
//
// The KalkanCrypt SDK header used by this package exposes KC_GetTokens without
// a buffer-capacity parameter. The wrapper can retry after KCR_BUFFER_TOO_SMALL,
// but it cannot make this native call memory-safe in-process because the native
// library is not told the Go allocation size. Backend services should run this
// method behind a worker process or process pool.
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

	return c.callListLocked(func(capacity int) (kalkancrypt.ListResult, error) {
		return ctx.GetTokens(nativeStorage, capacity)
	})
}

// GetCertificatesList calls KC_GetCertificatesList and returns the raw alias list
// plus native count.
//
// The SDK function used here is not length-aware: it receives a char* and count
// pointer, but no buffer capacity. Retries after KCR_BUFFER_TOO_SMALL improve
// compatibility; they are not an in-process memory-safety guarantee. Backend
// services should run this method behind a worker process or process pool.
func (c *Client) GetCertificatesList() (ListResult, error) {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[tokenStoreContext](c, "GetCertificatesList")
	if err != nil {
		return ListResult{}, err
	}

	return c.callListLocked(func(capacity int) (kalkancrypt.ListResult, error) {
		return ctx.GetCertificatesList(capacity)
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
