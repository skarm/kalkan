//go:build windows && amd64

package kalkancrypt

import "runtime"

func (h *windowsDriver) VerifyXML(alias string, flags int, xml []byte, capacity int) (BufferResult, error) {
	cAlias, err := narrowString(alias)
	if err != nil {
		return BufferResult{}, err
	}
	in, inLen, err := inputBytes(xml)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity)
	code := callWindowsStatus(h.funcs.verifyXML, bytesPtr(cAlias), intArg(flags), bytesPtr(in), uintptr(uint32(inLen)), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(cAlias)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *windowsDriver) GetCertFromXML(xml []byte, signID, capacity int) (BufferResult, error) {
	in, inLen, err := inputBytes(xml)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity)
	code := callWindowsStatus(h.funcs.getCertFromXML, bytesPtr(in), uintptr(uint32(inLen)), intArg(signID), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *windowsDriver) GetSigAlgFromXML(xml []byte, capacity int) (BufferResult, error) {
	in, inLen, err := inputBytes(xml)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity)
	code := callWindowsStatus(h.funcs.getSigAlgFromXML, bytesPtr(in), uintptr(uint32(inLen)), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
