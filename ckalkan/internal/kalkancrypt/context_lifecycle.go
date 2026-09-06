package kalkancrypt

// Init initializes the process-global KalkanCrypt runtime and returns its
// native status code.
func (c *Context) Init() uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.Init()
}

// InitDebug invokes native debug initialization when the context is open.
func (c *Context) InitDebug() {
	if !c.closed() {
		c.driver.InitDebug()
	}
}

// Finalize releases the native runtime resources without unloading the
// shared library. It does nothing for a closed context.
func (c *Context) Finalize() {
	if !c.closed() {
		c.driver.Finalize()
	}
}

// XMLFinalize releases native XML resources without unloading the library.
// It does nothing for a closed context.
func (c *Context) XMLFinalize() {
	if !c.closed() {
		c.driver.XMLFinalize()
	}
}

// LastError returns the native process-global error code, or
// KCR_LIBRARYNOTINITIALIZED when the context is closed.
func (c *Context) LastError() uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.LastError()
}

// LastErrorString retrieves the native diagnostic using capacity bytes of
// output storage and returns its status and reported length.
func (c *Context) LastErrorString(capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.LastErrorString(capacity)
}
