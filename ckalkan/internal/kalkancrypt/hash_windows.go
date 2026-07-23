//go:build windows && amd64

package kalkancrypt

import "runtime"

func (h *windowsDriver) HashData(call HashDataCall) (BufferResult, error) {
	cAlgorithm, err := narrowString(call.Algorithm)
	if err != nil {
		return BufferResult{}, err
	}
	in, inLen, err := inputBytesWithFlags(call.Data, call.Flags)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(call.Capacity)
	code := callWindowsStatus(h.funcs.hashData, bytesPtr(cAlgorithm), intArg(call.Flags), bytesPtr(in), uintptr(uint32(inLen)), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(cAlgorithm)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
