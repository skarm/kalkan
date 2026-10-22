//go:build linux && amd64 && cgo

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

import (
	"io"
	"math"
	"os"
	"runtime"
)

// HashData returns the digest and native status for call.Data with
// call.Algorithm and call.Flags. It uses call.Capacity bytes of output storage
// without retries.
func (h *linuxDriver) HashData(call HashDataCall) (BufferResult, error) {
	cAlgorithm, freeAlgorithm, err := cString(call.Algorithm)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeAlgorithm()

	flags, data := call.Flags, call.Data
	if flags&(inFileFlag|inBase64Flag) == inFileFlag|inBase64Flag {
		// The SDK handles InBase64 before InFile and otherwise decodes the
		// path itself. Read the file, then let the SDK decode its contents.
		data, err = readBase64HashFile(string(data))
		if err != nil {
			return BufferResult{}, err
		}

		flags &^= inFileFlag
	}

	in, inLen, err := inputBytesWithFlags(data, flags)
	if err != nil {
		return BufferResult{}, err
	}

	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(call.Capacity)
	code := C.bridge_hash_data(h.funcs, cAlgorithm, C.int(flags), charPtr(in), inLen, ucharPtr(buf), &outLen)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return bufferResult(uint64(code), buf, int(outLen)), nil
}

func readBase64HashFile(path string) ([]byte, error) {
	if err := checkNativeString(path); err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if err := checkNativeInputLength(info.Size()); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(io.LimitReader(file, int64(math.MaxInt32)+1))
	if err != nil {
		return nil, err
	}

	if err := checkNativeBytes(data); err != nil {
		return nil, err
	}

	return data, nil
}
