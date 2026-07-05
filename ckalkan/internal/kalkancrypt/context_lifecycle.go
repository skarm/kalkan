package kalkancrypt

// Init calls KC_Init.
func (c *Context) Init() uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.Init()
}

// InitDebug calls KC_InitDebug.
func (c *Context) InitDebug() {
	if !c.closed() {
		c.driver.InitDebug()
	}
}

// Finalize calls KC_Finalize.
func (c *Context) Finalize() {
	if !c.closed() {
		c.driver.Finalize()
	}
}

// XMLFinalize calls KC_XMLFinalize.
func (c *Context) XMLFinalize() {
	if !c.closed() {
		c.driver.XMLFinalize()
	}
}

// LastError calls KC_GetLastError.
func (c *Context) LastError() uint64 {
	if c.closed() {
		return errorLibraryNotInitialized
	}

	return c.driver.LastError()
}

// LastErrorString calls KC_GetLastErrorString.
func (c *Context) LastErrorString(capacity int) (BufferResult, error) {
	if c.closed() {
		return BufferResult{}, ErrClosed
	}

	return c.driver.LastErrorString(capacity)
}
