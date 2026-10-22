//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"
)

// Init initializes the native runtime and returns its status.
func (h *windowsDriver) Init() uint64 {
	return callWindowsStatus(h.funcs.init)
}

// InitDebug invokes the native debug initializer if it is available.
func (h *windowsDriver) InitDebug() {
	callWindowsVoid(h.funcs.initDebug)
}

// Finalize releases native runtime resources and leaves the library loaded.
func (h *windowsDriver) Finalize() {
	callWindowsVoid(h.funcs.finalize)
}

// XMLFinalize releases native XML resources and leaves the library loaded.
func (h *windowsDriver) XMLFinalize() {
	callWindowsVoid(h.funcs.xmlFinalize)
}

// LastError returns the native error code.
func (h *windowsDriver) LastError() uint64 {
	return callWindowsStatus(h.funcs.getLastError)
}

// LastErrorString returns native error text and its status within capacity
// bytes.
func (h *windowsDriver) LastErrorString(capacity int) (BufferResult, error) {
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity)
	code := callWindowsStatus(h.funcs.getLastErrorString, uintptr(unsafe.Pointer(bytesPtr(buf))), uintptr(unsafe.Pointer(&outLen)))
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}
