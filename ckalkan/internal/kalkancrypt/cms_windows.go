//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"
)

func (h *windowsDriver) GetTimeFromSig(data []byte, flags, sigID int) (uint64, int64) {
	in, inLen, err := cmsInputBytes(data, flags)
	if err != nil {
		return errorParam, 0
	}

	var out int64
	code := callWindowsStatus(
		h.funcs.getTimeFromSig,
		uintptr(unsafe.Pointer(bytesPtr(in))),
		uintptr(uint32(inLen)),
		intArg(flags),
		intArg(sigID),
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(in)

	return code, out
}

func (h *windowsDriver) GetCertFromCMS(call GetCertFromCMSCall) (BufferResult, error) {
	// The extraction API receives in-memory CMS, including binary NUL bytes,
	// even when the caller retained KC_IN_FILE in the native flags.
	in, inLen, err := cmsInputBytes(call.CMS, call.Flags&^inFileFlag)
	if err != nil {
		return BufferResult{}, err
	}

	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(call.Capacity)
	code := callWindowsStatus(
		h.funcs.getCertFromCMS,
		uintptr(unsafe.Pointer(bytesPtr(in))),
		uintptr(uint32(inLen)),
		intArg(call.SignID),
		intArg(call.Flags),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}
