//go:build linux && cgo

package kalkancrypt

/*
#include "KalkanCrypt.h"

static unsigned long bridge_hash_data(void *funcsPtr, char *algorithm, int flags, char *inData, int inDataLength, unsigned char *outData, int *outDataLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->HashData == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->HashData(algorithm, flags, inData, inDataLength, outData, outDataLength);
}
*/
import "C"

import "runtime"

func (h *linuxDriver) HashData(call HashDataCall) (BufferResult, error) {
	cAlgorithm, freeAlgorithm, err := cString(call.Algorithm)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeAlgorithm()

	in, inLen, err := inputBytes(call.Data)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(call.Capacity)
	code := C.bridge_hash_data(h.funcs, cAlgorithm, C.int(call.Flags), charPtr(in), inLen, ucharPtr(buf), &outLen)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
