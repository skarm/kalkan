package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

// SetTSAURL configures the timestamp authority URL through KC_TSASetUrl.
// The SDK function returns no status, so success does not confirm that
// KalkanCrypt accepted the URL or that the TSA server is reachable. Wrapper
// and session errors can still be returned.
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

// SetProxy applies the native HTTP proxy mode and connection parameters in
// req. Authentication and enablement are selected by req.Flags.
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
