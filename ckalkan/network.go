package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// SetTSAURL configures the timestamp authority URL through KC_TSASetUrl.
// The SDK function returns no status.
// Success does not confirm URL acceptance or server availability.
// The method can still return wrapper and session errors.
func (c *Client) SetTSAURL(tsaURL string) error {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[networkContext](c, "SetTSAURL")
	if err != nil {
		return err
	}

	c.clearErrorLocked()

	return c.wrapCodeLocked(ErrorCode(ctx.SetTSAURL(tsaURL)))
}

// SetProxy applies the native HTTP proxy mode and connection parameters in req.
// req.Flags selects authentication and proxy use.
func (c *Client) SetProxy(req ProxyRequest) error {
	nativeFlags, err := flagsToNativeInt(req.Flags)
	if err != nil {
		return err
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[networkContext](c, "SetProxy")
	if err != nil {
		return err
	}

	c.clearErrorLocked()

	return c.wrapCodeLocked(ErrorCode(ctx.SetProxy(kalkancrypt.ProxyCall{
		Flags:    nativeFlags,
		Address:  req.Address,
		Port:     req.Port,
		User:     req.User,
		Password: req.Password,
	})))
}
