//go:build linux && cgo

package kalkancrypt

/*
#include "KalkanCrypt.h"

static unsigned long bridge_x509_load_certificate_from_file(void *funcsPtr, char *certPath, int certType) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->X509LoadCertificateFromFile == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->X509LoadCertificateFromFile(certPath, certType);
}

static unsigned long bridge_x509_load_certificate_from_buffer(void *funcsPtr, unsigned char *inCert, int certLength, int flag) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->X509LoadCertificateFromBuffer == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->X509LoadCertificateFromBuffer(inCert, certLength, flag);
}

static unsigned long bridge_x509_export_certificate_from_store(void *funcsPtr, char *alias, int flag, char *outCert, int *outCertLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->X509ExportCertificateFromStore == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->X509ExportCertificateFromStore(alias, flag, outCert, outCertLength);
}

static unsigned long bridge_x509_certificate_get_info(void *funcsPtr, char *inCert, int inCertLength, int propId, unsigned char *outData, int *outDataLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->X509CertificateGetInfo == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->X509CertificateGetInfo(inCert, inCertLength, propId, outData, outDataLength);
}

static unsigned long bridge_x509_validate_certificate(void *funcsPtr, char *inCert, int inCertLength, int validType, char *validPath, long long checkTime, char *outInfo, int *outInfoLength, int flag, char *getOCSPResponse, int *getOCSPResponseLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->X509ValidateCertificate == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->X509ValidateCertificate(inCert, inCertLength, validType, validPath, checkTime, outInfo, outInfoLength, flag, getOCSPResponse, getOCSPResponseLength);
}
*/
import "C"

import "runtime"

func (h *linuxDriver) X509LoadCertificateFromFile(certPath string, certType int) uint64 {
	path, freePath, err := cString(certPath)
	if err != nil {
		return errorParam
	}
	defer freePath()

	return uint64(C.bridge_x509_load_certificate_from_file(h.funcs, path, C.int(certType)))
}

func (h *linuxDriver) X509LoadCertificateFromBuffer(cert []byte, format int) uint64 {
	in, inLen, err := inputBytes(cert)
	if err != nil {
		return errorParam
	}
	code := C.bridge_x509_load_certificate_from_buffer(h.funcs, ucharPtr(in), inLen, C.int(format))
	runtime.KeepAlive(in)

	return uint64(code)
}

func (h *linuxDriver) X509ExportCertificateFromStore(alias string, format, capacity int) (BufferResult, error) {
	cAlias, freeAlias, err := cString(alias)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeAlias()

	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(capacity)
	code := C.bridge_x509_export_certificate_from_store(h.funcs, cAlias, C.int(format), charPtr(buf), &outLen)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *linuxDriver) X509CertificateGetInfo(cert []byte, prop, capacity int) (BufferResult, error) {
	in, inLen, err := inputBytes(cert)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(capacity)
	code := C.bridge_x509_certificate_get_info(h.funcs, charPtr(in), inLen, C.int(prop), ucharPtr(buf), &outLen)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *linuxDriver) X509ValidateCertificate(call ValidateCertificateCall) (ValidateResult, error) {
	in, inLen, err := inputBytes(call.Certificate)
	if err != nil {
		return ValidateResult{}, err
	}
	validPath, freeValidPath, err := cString(call.ValidationPath)
	if err != nil {
		return ValidateResult{}, err
	}
	defer freeValidPath()

	infoBuf, err := outputBuffer(call.InfoCapacity)
	if err != nil {
		return ValidateResult{}, err
	}
	ocspBuf, err := outputBuffer(call.OCSPCapacity)
	if err != nil {
		return ValidateResult{}, err
	}

	infoLen := C.int(call.InfoCapacity)
	ocspLen := C.int(call.OCSPCapacity)
	code := C.bridge_x509_validate_certificate(
		h.funcs,
		charPtr(in),
		inLen,
		C.int(call.ValidationType),
		validPath,
		C.longlong(call.CheckTimeUnix),
		charPtr(infoBuf),
		&infoLen,
		C.int(call.Flags),
		charPtr(ocspBuf),
		&ocspLen,
	)
	runtime.KeepAlive(in)
	runtime.KeepAlive(infoBuf)
	runtime.KeepAlive(ocspBuf)

	return ValidateResult{
		Code:    uint64(code),
		Info:    boundedBytes(infoBuf, int(infoLen)),
		InfoLen: int(infoLen),
		OCSP:    boundedBytes(ocspBuf, int(ocspLen)),
		OCSPLen: int(ocspLen),
	}, nil
}
