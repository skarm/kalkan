//go:build linux && cgo

package kalkancrypt

/*
#include "KalkanCrypt.h"

static unsigned long bridge_get_tokens(void *funcsPtr, unsigned long storage, char *tokens, unsigned long *tk_count) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_GetTokens == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_GetTokens(storage, tokens, tk_count);
}

static unsigned long bridge_get_certificates_list(void *funcsPtr, char *certificates, unsigned long *cert_count) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_GetCertificatesList == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_GetCertificatesList(certificates, cert_count);
}
*/
import "C"

import "runtime"

func (h *linuxDriver) GetTokens(storage uint64, bufferSize int) (ListResult, error) {
	// KC_GetTokens has no capacity parameter in KalkanCrypt.h; bufferSize only
	// sizes the Go allocation before entering the native library.
	buf, err := outputBuffer(bufferSize)
	if err != nil {
		return ListResult{}, err
	}

	var count C.ulong
	code := C.bridge_get_tokens(h.funcs, C.ulong(storage), charPtr(buf), &count)
	runtime.KeepAlive(buf)

	return ListResult{Code: uint64(code), Data: string(trimCStringBytes(buf)), Count: uint64(count)}, nil
}

func (h *linuxDriver) GetCertificatesList(bufferSize int) (ListResult, error) {
	// KC_GetCertificatesList has no capacity parameter in KalkanCrypt.h; bufferSize
	// only sizes the Go allocation before entering the native library.
	buf, err := outputBuffer(bufferSize)
	if err != nil {
		return ListResult{}, err
	}

	var count C.ulong
	code := C.bridge_get_certificates_list(h.funcs, charPtr(buf), &count)
	runtime.KeepAlive(buf)

	return ListResult{Code: uint64(code), Data: string(trimCStringBytes(buf)), Count: uint64(count)}, nil
}
