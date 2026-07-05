//go:build windows && amd64

package kalkancrypt

import "runtime"

func (h *windowsDriver) GetTimeFromSig(data []byte, flags, sigID int) (uint64, int64) {
	in, inLen, err := inputBytes(data)
	if err != nil {
		return errorParam, 0
	}
	var out int64
	code := callWindowsStatus(h.funcs.getTimeFromSig, bytesPtr(in), uintptr(uint32(inLen)), intArg(flags), intArg(sigID), int64Ptr(&out))
	runtime.KeepAlive(in)

	return code, out
}

func (h *windowsDriver) GetCertFromCMS(cms []byte, signID, flags, capacity int) (BufferResult, error) {
	in, inLen, err := inputBytes(cms)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity)
	code := callWindowsStatus(h.funcs.getCertFromCMS, bytesPtr(in), uintptr(uint32(inLen)), intArg(signID), intArg(flags), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
