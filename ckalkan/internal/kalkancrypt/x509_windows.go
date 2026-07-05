//go:build windows && amd64

package kalkancrypt

import "runtime"

func (h *windowsDriver) X509LoadCertificateFromFile(certPath string, certType int) uint64 {
	path, err := narrowString(certPath)
	if err != nil {
		return errorParam
	}
	code := callWindowsStatus(h.funcs.x509LoadCertificateFile, bytesPtr(path), intArg(certType))
	runtime.KeepAlive(path)

	return code
}

func (h *windowsDriver) X509LoadCertificateFromBuffer(cert []byte, format int) uint64 {
	in, inLen, err := inputBytes(cert)
	if err != nil {
		return errorParam
	}
	code := callWindowsStatus(h.funcs.x509LoadCertificateBuffer, bytesPtr(in), uintptr(uint32(inLen)), intArg(format))
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
	code := callWindowsStatus(h.funcs.x509ExportCertStore, bytesPtr(cAlias), intArg(format), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(cAlias)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
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
	code := callWindowsStatus(h.funcs.x509CertificateGetInfo, bytesPtr(in), uintptr(uint32(inLen)), intArg(prop), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *windowsDriver) X509ValidateCertificate(call ValidateCertificateCall) (ValidateResult, error) {
	in, inLen, err := inputBytes(call.Certificate)
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
	args := []uintptr{
		bytesPtr(in),
		uintptr(uint32(inLen)),
		intArg(call.ValidationType),
		bytesPtr(validPath),
	}
	args = append(args, uintptr(uint64(call.CheckTimeUnix)))
	args = append(args,
		bytesPtr(infoBuf),
		int32Ptr(&infoLen),
		intArg(call.Flags),
		bytesPtr(ocspBuf),
		int32Ptr(&ocspLen),
	)

	code := callWindowsStatus(h.funcs.x509ValidateCertificate, args...)
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
