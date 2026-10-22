//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"

	"github.com/skarm/kalkan/internal/nativebytes"
)

// GetTokens returns the native status, token list, and item count for storage.
// bufferSize controls the Go allocation only. The native API receives no output
// capacity.
func (h *windowsDriver) GetTokens(storage uint64, bufferSize int) (ListResult, error) {
	// KC_GetTokens has no capacity parameter in KalkanCrypt.h.
	// bufferSize controls the Go allocation only.
	buf, err := outputBuffer(bufferSize)
	if err != nil {
		return ListResult{}, err
	}

	var count uint32
	code := callWindowsStatus(h.funcs.getTokens, ulongArg(storage), uintptr(unsafe.Pointer(bytesPtr(buf))), uintptr(unsafe.Pointer(&count)))
	runtime.KeepAlive(buf)

	return ListResult{Code: code, Data: string(nativebytes.BeforeNUL(buf)), Count: uint64(count)}, nil
}

// GetCertificatesList returns the native status, certificate list, and item
// count. bufferSize controls the Go allocation only. The native API receives no
// output capacity.
func (h *windowsDriver) GetCertificatesList(bufferSize int) (ListResult, error) {
	// KC_GetCertificatesList has no capacity parameter in KalkanCrypt.h.
	// bufferSize controls the Go allocation only.
	buf, err := outputBuffer(bufferSize)
	if err != nil {
		return ListResult{}, err
	}

	var count uint32
	code := callWindowsStatus(h.funcs.getCertificatesList, uintptr(unsafe.Pointer(bytesPtr(buf))), uintptr(unsafe.Pointer(&count)))
	runtime.KeepAlive(buf)

	return ListResult{Code: code, Data: string(nativebytes.BeforeNUL(buf)), Count: uint64(count)}, nil
}
