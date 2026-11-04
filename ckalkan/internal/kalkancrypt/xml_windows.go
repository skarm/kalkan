//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"
)

// VerifyXML returns the native verification status and diagnostics for call.XML
// with call.Flags and call.Alias.
func (h *windowsDriver) VerifyXML(call VerifyXMLCall) (BufferResult, error) {
	cAlias, err := narrowString(call.Alias)
	if err != nil {
		return BufferResult{}, err
	}

	in, inLen, err := inputBytes(call.XML)
	if err != nil {
		return BufferResult{}, err
	}

	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(call.Capacity) //nolint:gosec // outputBuffer validates the capacity against the native C int range.
	code := callWindowsStatus(
		h.funcs.verifyXML,
		uintptr(unsafe.Pointer(bytesPtr(cAlias))),
		intArg(call.Flags),
		uintptr(unsafe.Pointer(bytesPtr(in))),
		uintptr(uint32(inLen)), //nolint:gosec // inputBytes validates the logical length against the native C int range.
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(cAlias)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}

// GetCertFromXML returns the certificate selected by signID in xml and its
// native status. It uses capacity bytes of output storage.
func (h *windowsDriver) GetCertFromXML(xml []byte, signID, capacity int) (BufferResult, error) {
	in, inLen, err := inputBytes(xml)
	if err != nil {
		return BufferResult{}, err
	}

	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity) //nolint:gosec // outputBuffer validates the capacity against the native C int range.
	code := callWindowsStatus(
		h.funcs.getCertFromXML,
		uintptr(unsafe.Pointer(bytesPtr(in))),
		uintptr(uint32(inLen)), //nolint:gosec // inputBytes validates the logical length against the native C int range.
		intArg(signID),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}

// GetSigAlgFromXML returns the signature algorithm identifier in xml and its
// native status. It uses capacity bytes of output storage.
func (h *windowsDriver) GetSigAlgFromXML(xml []byte, capacity int) (BufferResult, error) {
	in, inLen, err := inputBytes(xml)
	if err != nil {
		return BufferResult{}, err
	}

	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity) //nolint:gosec // outputBuffer validates the capacity against the native C int range.
	code := callWindowsStatus(
		h.funcs.getSigAlgFromXML,
		uintptr(unsafe.Pointer(bytesPtr(in))),
		uintptr(uint32(inLen)), //nolint:gosec // inputBytes validates the logical length against the native C int range.
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}
