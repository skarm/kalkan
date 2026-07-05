package ckalkan

// Init calls KC_Init.
func (c *Client) Init() error {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[lifecycleContext](c, "Init")
	if err != nil {
		return err
	}

	c.clearErrorLocked()

	return c.wrapCodeLocked(ErrorCode(ctx.Init()))
}

// InitDebug calls KC_InitDebug.
func (c *Client) InitDebug() error {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[lifecycleContext](c, "InitDebug")
	if err != nil {
		return err
	}

	c.clearErrorLocked()
	ctx.InitDebug()

	return nil
}

// Finalize calls KC_Finalize.
func (c *Client) Finalize() error {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[lifecycleContext](c, "Finalize")
	if err != nil {
		return err
	}

	c.clearErrorLocked()
	ctx.Finalize()

	return nil
}

// XMLFinalize calls KC_XMLFinalize.
func (c *Client) XMLFinalize() error {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[lifecycleContext](c, "XMLFinalize")
	if err != nil {
		return err
	}

	c.clearErrorLocked()
	ctx.XMLFinalize()

	return nil
}

// GetLastError calls KC_GetLastError.
func (c *Client) GetLastError() ErrorCode {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[lifecycleContext](c, "GetLastError")
	if err != nil {
		return ErrorLibraryNotInitialized
	}

	return ErrorCode(ctx.LastError())
}

// GetLastErrorString calls KC_GetLastErrorString.
func (c *Client) GetLastErrorString() (ErrorCode, string) {
	process.mu.Lock()
	defer process.mu.Unlock()

	if err := c.ensureOpenLocked(); err != nil {
		return ErrorLibraryNotInitialized, err.Error()
	}

	return c.lastErrorStringLocked()
}
