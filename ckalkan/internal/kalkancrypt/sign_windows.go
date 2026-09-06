//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"
)

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
	code := callWindowsStatus(
		h.funcs.signHash,
		uintptr(unsafe.Pointer(bytesPtr(cAlias))),
		intArg(call.Flags),
		uintptr(unsafe.Pointer(bytesPtr(in))),
		uintptr(uint32(inLen)),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(cAlias)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}

func (h *windowsDriver) SignData(call SignDataCall) (BufferResult, error) {
	cAlias, err := narrowString(call.Alias)
	if err != nil {
		return BufferResult{}, err
	}

	inData, inDataLen, err := cmsInputBytes(call.Data, call.Flags)
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
		uintptr(unsafe.Pointer(bytesPtr(cAlias))),
		intArg(call.Flags),
		uintptr(unsafe.Pointer(bytesPtr(inData))),
		uintptr(uint32(inDataLen)),
		uintptr(unsafe.Pointer(bytesPtr(inSig))),
		uintptr(uint32(inSigLen)),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(cAlias)
	runtime.KeepAlive(inData)
	runtime.KeepAlive(inSig)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
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
		uintptr(unsafe.Pointer(bytesPtr(alias))),
		intArg(call.Flags),
		uintptr(unsafe.Pointer(bytesPtr(xml))),
		uintptr(uint32(xmlLen)),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
		uintptr(unsafe.Pointer(bytesPtr(signNodeID))),
		uintptr(unsafe.Pointer(bytesPtr(parentSignNode))),
		uintptr(unsafe.Pointer(bytesPtr(parentNamespace))),
	)
	runtime.KeepAlive(alias)
	runtime.KeepAlive(xml)
	runtime.KeepAlive(signNodeID)
	runtime.KeepAlive(parentSignNode)
	runtime.KeepAlive(parentNamespace)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
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
		uintptr(unsafe.Pointer(bytesPtr(alias))),
		ulongArg(call.Flags),
		uintptr(unsafe.Pointer(bytesPtr(xml))),
		uintptr(uint32(xmlLen)),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
		uintptr(unsafe.Pointer(bytesPtr(signNodeID))),
	)
	runtime.KeepAlive(alias)
	runtime.KeepAlive(xml)
	runtime.KeepAlive(signNodeID)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}
