//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"
)

// HashData returns the digest and native status for call.Data with
// call.Algorithm and call.Flags. It uses call.Capacity bytes of output storage
// without retries.
func (h *windowsDriver) HashData(call HashDataCall) (BufferResult, error) {
	cAlgorithm, err := narrowString(call.Algorithm)
	if err != nil {
		return BufferResult{}, err
	}

	in, inLen, err := inputBytesWithFlags(call.Data, call.Flags)
	if err != nil {
		return BufferResult{}, err
	}

	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(call.Capacity)
	code := callWindowsStatus(
		h.funcs.hashData,
		uintptr(unsafe.Pointer(bytesPtr(cAlgorithm))),
		intArg(call.Flags),
		uintptr(unsafe.Pointer(bytesPtr(in))),
		uintptr(uint32(inLen)),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(cAlgorithm)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}
