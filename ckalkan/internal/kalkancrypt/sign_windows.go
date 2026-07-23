//go:build windows && amd64

package kalkancrypt

import "runtime"

func (h *windowsDriver) SignHash(call SignHashCall) (BufferResult, error) {
	cAlias, err := narrowString(call.Alias)
	if err != nil {
		return BufferResult{}, err
	}
	in, inLen, err := inputBytes(call.Hash)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(call.Capacity)
	code := callWindowsStatus(h.funcs.signHash, bytesPtr(cAlias), intArg(call.Flags), bytesPtr(in), uintptr(uint32(inLen)), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(cAlias)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *windowsDriver) SignData(call SignDataCall) (BufferResult, error) {
	cAlias, err := narrowString(call.Alias)
	if err != nil {
		return BufferResult{}, err
	}
	inData, inDataLen, err := inputBytesWithFlags(call.Data, call.Flags)
	if err != nil {
		return BufferResult{}, err
	}
	inSig, inSigLen, err := inputBytes(call.Signature)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(call.Capacity)
	code := callWindowsStatus(
		h.funcs.signData,
		bytesPtr(cAlias),
		intArg(call.Flags),
		bytesPtr(inData),
		uintptr(uint32(inDataLen)),
		bytesPtr(inSig),
		uintptr(uint32(inSigLen)),
		bytesPtr(buf),
		int32Ptr(&outLen),
	)
	runtime.KeepAlive(cAlias)
	runtime.KeepAlive(inData)
	runtime.KeepAlive(inSig)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *windowsDriver) SignXML(call SignXMLCall) (BufferResult, error) {
	alias, err := narrowString(call.Alias)
	if err != nil {
		return BufferResult{}, err
	}
	xml, xmlLen, err := inputBytes(call.XML)
	if err != nil {
		return BufferResult{}, err
	}
	signNodeID, err := narrowString(call.SignNodeID)
	if err != nil {
		return BufferResult{}, err
	}
	parentSignNode, err := narrowString(call.ParentSignNode)
	if err != nil {
		return BufferResult{}, err
	}
	parentNamespace, err := narrowString(call.ParentNamespace)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(call.Capacity)
	code := callWindowsStatus(
		h.funcs.signXML,
		bytesPtr(alias),
		intArg(call.Flags),
		bytesPtr(xml),
		uintptr(uint32(xmlLen)),
		bytesPtr(buf),
		int32Ptr(&outLen),
		bytesPtr(signNodeID),
		bytesPtr(parentSignNode),
		bytesPtr(parentNamespace),
	)
	runtime.KeepAlive(alias)
	runtime.KeepAlive(xml)
	runtime.KeepAlive(signNodeID)
	runtime.KeepAlive(parentSignNode)
	runtime.KeepAlive(parentNamespace)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *windowsDriver) SignWSSE(call SignWSSECall) (BufferResult, error) {
	alias, err := narrowString(call.Alias)
	if err != nil {
		return BufferResult{}, err
	}
	xml, xmlLen, err := inputBytes(call.XML)
	if err != nil {
		return BufferResult{}, err
	}
	signNodeID, err := narrowString(call.SignNodeID)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(call.Capacity)
	code := callWindowsStatus(
		h.funcs.signWSSE,
		bytesPtr(alias),
		ulongArg(call.Flags),
		bytesPtr(xml),
		uintptr(uint32(xmlLen)),
		bytesPtr(buf),
		int32Ptr(&outLen),
		bytesPtr(signNodeID),
	)
	runtime.KeepAlive(alias)
	runtime.KeepAlive(xml)
	runtime.KeepAlive(signNodeID)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
