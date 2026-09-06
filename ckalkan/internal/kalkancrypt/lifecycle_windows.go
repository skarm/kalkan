//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"
)

func (h *windowsDriver) Init() uint64 {
	return callWindowsStatus(h.funcs.init)
}

func (h *windowsDriver) InitDebug() {
	callWindowsVoid(h.funcs.initDebug)
}

func (h *windowsDriver) Finalize() {
	callWindowsVoid(h.funcs.finalize)
}

func (h *windowsDriver) XMLFinalize() {
	callWindowsVoid(h.funcs.xmlFinalize)
}

func (h *windowsDriver) LastError() uint64 {
	return callWindowsStatus(h.funcs.getLastError)
}

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
