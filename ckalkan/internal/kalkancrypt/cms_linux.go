//go:build linux && cgo

package kalkancrypt

/*
#include <time.h>
#include "KalkanCrypt.h"

static unsigned long bridge_get_time_from_sig(void *funcsPtr, char *inData, int inDataLength, int flags, int inSigId, time_t *outDateTime) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_GetTimeFromSig == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_GetTimeFromSig(inData, inDataLength, flags, inSigId, outDateTime);
}

static unsigned long bridge_get_cert_from_cms(void *funcsPtr, char *inCMS, int inCMSLen, int inSignId, int flags, char *outCert, int *outCertLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_GetCertFromCMS == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_GetCertFromCMS(inCMS, inCMSLen, inSignId, flags, outCert, outCertLength);
}
*/
import "C"

import "runtime"

func (h *linuxDriver) GetTimeFromSig(data []byte, flags, sigID int) (uint64, int64) {
	in, inLen, err := inputBytes(data)
	if err != nil {
		return errorParam, 0
	}
	var out C.time_t
	code := C.bridge_get_time_from_sig(h.funcs, charPtr(in), inLen, C.int(flags), C.int(sigID), &out)
	runtime.KeepAlive(in)

	return uint64(code), int64(out)
}

func (h *linuxDriver) GetCertFromCMS(call GetCertFromCMSCall) (BufferResult, error) {
	in, inLen, err := inputBytes(call.CMS)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(call.Capacity)
	code := C.bridge_get_cert_from_cms(h.funcs, charPtr(in), inLen, C.int(call.SignID), C.int(call.Flags), charPtr(buf), &outLen)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
