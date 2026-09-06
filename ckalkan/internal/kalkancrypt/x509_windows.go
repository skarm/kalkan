//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"
)

func (h *windowsDriver) X509LoadCertificateFromFile(certPath string, certType int) uint64 {
	path, err := narrowString(certPath)
	if err != nil {
		return errorParam
	}

	code := callWindowsStatus(h.funcs.x509LoadCertificateFile, uintptr(unsafe.Pointer(bytesPtr(path))), intArg(certType))
	runtime.KeepAlive(path)

	return code
}

func (h *windowsDriver) X509LoadCertificateFromBuffer(cert []byte, format int) uint64 {
	in, inLen, err := inputBytes(cert)
	if err != nil {
		return errorParam
	}

	code := callWindowsStatus(h.funcs.x509LoadCertificateBuffer, uintptr(unsafe.Pointer(bytesPtr(in))), uintptr(uint32(inLen)), intArg(format))
	runtime.KeepAlive(in)

	return code
}

func (h *windowsDriver) X509ExportCertificateFromStore(alias string, format, capacity int) (BufferResult, error) {
	cAlias, err := narrowString(alias)
	if err != nil {
		return BufferResult{}, err
	}

	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity)
	code := callWindowsStatus(
		h.funcs.x509ExportCertStore,
		uintptr(unsafe.Pointer(bytesPtr(cAlias))),
		intArg(format),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(cAlias)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}

func (h *windowsDriver) X509CertificateGetInfo(cert []byte, prop, capacity int) (BufferResult, error) {
	in, inLen, err := inputBytes(cert)
	if err != nil {
		return BufferResult{}, err
	}

	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity)
	code := callWindowsStatus(
		h.funcs.x509CertificateGetInfo,
		uintptr(unsafe.Pointer(bytesPtr(in))),
		uintptr(uint32(inLen)),
		intArg(prop),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}

func (h *windowsDriver) X509ValidateCertificate(call ValidateCertificateCall) (ValidateResult, error) {
	in, inLen, err := inputBytesWithFlags(call.Certificate, call.Flags)
	if err != nil {
		return ValidateResult{}, err
	}

	validPath, err := narrowString(call.ValidationPath)
	if err != nil {
		return ValidateResult{}, err
	}

	infoBuf, err := outputBuffer(call.InfoCapacity)
	if err != nil {
		return ValidateResult{}, err
	}

	ocspBuf, err := outputBuffer(call.OCSPCapacity)
	if err != nil {
		return ValidateResult{}, err
	}

	infoLen := int32(call.InfoCapacity)
	ocspLen := int32(call.OCSPCapacity)
	code := callWindowsStatus(h.funcs.x509ValidateCertificate,
		uintptr(unsafe.Pointer(bytesPtr(in))),
		uintptr(uint32(inLen)),
		intArg(call.ValidationType),
		uintptr(unsafe.Pointer(bytesPtr(validPath))),
		uintptr(uint64(call.CheckTimeUnix)),
		uintptr(unsafe.Pointer(bytesPtr(infoBuf))),
		uintptr(unsafe.Pointer(&infoLen)),
		intArg(call.Flags),
		uintptr(unsafe.Pointer(bytesPtr(ocspBuf))),
		uintptr(unsafe.Pointer(&ocspLen)),
	)
	runtime.KeepAlive(in)
	runtime.KeepAlive(validPath)
	runtime.KeepAlive(infoBuf)
	runtime.KeepAlive(ocspBuf)

	return ValidateResult{
		Code:    code,
		Info:    boundedBytes(infoBuf, int(infoLen)),
		InfoLen: int(infoLen),
		OCSP:    boundedBytes(ocspBuf, int(ocspLen)),
		OCSPLen: int(ocspLen),
	}, nil
}
