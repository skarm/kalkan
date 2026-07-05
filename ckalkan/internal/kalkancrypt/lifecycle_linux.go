//go:build linux && cgo

package kalkancrypt

/*
#include "KalkanCrypt.h"

static unsigned long bridge_init(void *funcsPtr) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_Init == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_Init();
}

static void bridge_init_debug(void *funcsPtr) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs != NULL && funcs->KC_InitDebug != NULL) funcs->KC_InitDebug();
}

static void bridge_finalize(void *funcsPtr) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs != NULL && funcs->KC_Finalize != NULL) funcs->KC_Finalize();
}

static void bridge_xml_finalize(void *funcsPtr) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs != NULL && funcs->KC_XMLFinalize != NULL) funcs->KC_XMLFinalize();
}

static unsigned long bridge_get_last_error(void *funcsPtr) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_GetLastError == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_GetLastError();
}

static unsigned long bridge_get_last_error_string(void *funcsPtr, char *errorString, int *bufSize) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_GetLastErrorString == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_GetLastErrorString(errorString, bufSize);
}
*/
import "C"

import "runtime"

func (h *linuxDriver) Init() uint64 {
	return uint64(C.bridge_init(h.funcs))
}

func (h *linuxDriver) InitDebug() {
	C.bridge_init_debug(h.funcs)
}

func (h *linuxDriver) Finalize() {
	C.bridge_finalize(h.funcs)
}

func (h *linuxDriver) XMLFinalize() {
	C.bridge_xml_finalize(h.funcs)
}

func (h *linuxDriver) LastError() uint64 {
	return uint64(C.bridge_get_last_error(h.funcs))
}

func (h *linuxDriver) LastErrorString(capacity int) (BufferResult, error) {
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(capacity)
	code := C.bridge_get_last_error_string(h.funcs, charPtr(buf), &outLen)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
