package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// SetTSAURL configures the timestamp authority URL through KC_TSASetUrl.
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

// SetProxy calls KC_SetProxy and configures the native HTTP proxy settings.
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
