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

func (h *linuxDriver) HashData(algorithm string, flags int, data []byte, capacity int) (BufferResult, error) {
	cAlgorithm, freeAlgorithm, err := cString(algorithm)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeAlgorithm()

	in, inLen, err := inputBytes(data)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(capacity)
	code := C.bridge_hash_data(h.funcs, cAlgorithm, C.int(flags), charPtr(in), inLen, ucharPtr(buf), &outLen)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
