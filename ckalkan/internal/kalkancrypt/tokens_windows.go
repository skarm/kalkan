//go:build windows && amd64

package kalkancrypt

import "runtime"

func (h *windowsDriver) GetTokens(storage uint64, bufferSize int) (ListResult, error) {
	// KC_GetTokens has no capacity parameter in KalkanCrypt.h; bufferSize only
	// sizes the Go allocation before entering the native library.
	buf, err := outputBuffer(bufferSize)
	if err != nil {
		return ListResult{}, err
	}

	var count uint32
	code := callWindowsStatus(h.funcs.getTokens, ulongArg(storage), bytesPtr(buf), uint32Ptr(&count))
	runtime.KeepAlive(buf)

	return ListResult{Code: code, Data: string(trimCStringBytes(buf)), Count: uint64(count)}, nil
}

func (h *windowsDriver) GetCertificatesList(bufferSize int) (ListResult, error) {
	// KC_GetCertificatesList has no capacity parameter in KalkanCrypt.h; bufferSize
	// only sizes the Go allocation before entering the native library.
	buf, err := outputBuffer(bufferSize)
	if err != nil {
		return ListResult{}, err
	}

	var count uint32
	code := callWindowsStatus(h.funcs.getCertificatesList, bytesPtr(buf), uint32Ptr(&count))
	runtime.KeepAlive(buf)

	return ListResult{Code: code, Data: string(trimCStringBytes(buf)), Count: uint64(count)}, nil
}
