//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"
)

func (h *windowsDriver) VerifyData(call VerifyDataCall) (VerifyResult, error) {
	return h.verifyData(call, false)
}

func (h *windowsDriver) UVerifyData(call VerifyDataCall) (VerifyResult, error) {
	return h.verifyData(call, true)
}

func (h *windowsDriver) verifyData(call VerifyDataCall, universal bool) (VerifyResult, error) {
	alias, err := narrowString(call.Alias)
	if err != nil {
		return VerifyResult{}, err
	}

	data, dataLen, err := inputBytes(call.Data)
	if err != nil {
		return VerifyResult{}, err
	}

	signature, signatureLen, err := verifySignatureInput(call.Signature, call.Flags, universal)
	if err != nil {
		return VerifyResult{}, err
	}

	dataBuf, err := outputBuffer(call.DataCapacity)
	if err != nil {
		return VerifyResult{}, err
	}

	infoBuf, err := outputBuffer(call.InfoCapacity)
	if err != nil {
		return VerifyResult{}, err
	}

	certBuf, err := outputBuffer(call.CertCapacity)
	if err != nil {
		return VerifyResult{}, err
	}

	dataOutLen := int32(call.DataCapacity)
	infoLen := int32(call.InfoCapacity)
	certLen := int32(call.CertCapacity)
	fn := h.funcs.verifyData
	if universal {
		fn = h.funcs.uverifyData
	}
	code := callWindowsStatus(
		fn,
		uintptr(unsafe.Pointer(bytesPtr(alias))),
		intArg(call.Flags),
		uintptr(unsafe.Pointer(bytesPtr(data))),
		uintptr(uint32(dataLen)),
		uintptr(unsafe.Pointer(bytesPtr(signature))),
		uintptr(uint32(signatureLen)),
		uintptr(unsafe.Pointer(bytesPtr(dataBuf))),
		uintptr(unsafe.Pointer(&dataOutLen)),
		uintptr(unsafe.Pointer(bytesPtr(infoBuf))),
		uintptr(unsafe.Pointer(&infoLen)),
		intArg(call.CertID),
		uintptr(unsafe.Pointer(bytesPtr(certBuf))),
		uintptr(unsafe.Pointer(&certLen)),
	)
	runtime.KeepAlive(alias)
	runtime.KeepAlive(data)
	runtime.KeepAlive(signature)
	runtime.KeepAlive(dataBuf)
	runtime.KeepAlive(infoBuf)
	runtime.KeepAlive(certBuf)

	return VerifyResult{
		Code:    code,
		Data:    boundedBytes(dataBuf, int(dataOutLen)),
		DataLen: int(dataOutLen),
		Info:    boundedBytes(infoBuf, int(infoLen)),
		InfoLen: int(infoLen),
		Cert:    boundedBytes(certBuf, int(certLen)),
		CertLen: int(certLen),
	}, nil
}
