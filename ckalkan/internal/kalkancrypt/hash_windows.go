//go:build windows && amd64

package kalkancrypt

import "runtime"

func (h *windowsDriver) HashData(algorithm string, flags int, data []byte, capacity int) (BufferResult, error) {
	cAlgorithm, err := narrowString(algorithm)
	if err != nil {
		return BufferResult{}, err
	}
	in, inLen, err := inputBytes(data)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity)
	code := callWindowsStatus(h.funcs.hashData, bytesPtr(cAlgorithm), intArg(flags), bytesPtr(in), uintptr(uint32(inLen)), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(cAlgorithm)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
