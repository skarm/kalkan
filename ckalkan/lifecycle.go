package ckalkan

// Init initializes the loaded KalkanCrypt runtime. Call it after [New] and
// before cryptographic operations. A nonzero native status becomes a [KalkanError].
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

// InitDebug invokes KalkanCrypt debug initialization. The native function
// returns no status; the method reports only client or capability errors.
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

// Finalize releases native runtime resources while keeping the library
// loaded. [Client.Close] also finalizes the runtime and unloads the library.
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

// XMLFinalize releases the native XML subsystem resources while keeping
// the library loaded. [Client.Close] performs this cleanup automatically.
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

// GetLastError returns the process-global native error code. It returns
// [ErrorLibraryNotInitialized] when the client or lifecycle capability is unavailable.
// Another goroutine's native call may change this diagnostic state.
func (c *Client) GetLastError() ErrorCode {
	process.mu.Lock()
	defer process.mu.Unlock()

	ctx, err := contextAsLocked[lifecycleContext](c, "GetLastError")
	if err != nil {
		return ErrorLibraryNotInitialized
	}

	return ErrorCode(ctx.LastError())
}

// GetLastErrorString returns the native diagnostic retrieval status and text,
// using bounded output retries. It reports [ErrorLibraryNotInitialized] for an
// unavailable client. Other native calls can change the diagnostic state.
func (c *Client) GetLastErrorString() (ErrorCode, string) {
	process.mu.Lock()
	defer process.mu.Unlock()

	if err := c.ensureOpenLocked(); err != nil {
		return ErrorLibraryNotInitialized, err.Error()
	}

	return c.lastErrorStringLocked()
}
