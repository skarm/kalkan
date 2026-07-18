//go:build linux && cgo

package kalkancrypt

/*
#include "KalkanCrypt.h"

static unsigned long bridge_verify_data(void *funcsPtr, char *alias, int flags, char *inData, int inDataLength, unsigned char *inoutSign, int inoutSignLength, char *outData, int *outDataLen, char *outVerifyInfo, int *outVerifyInfoLen, int inCertID, char *outCert, int *outCertLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->VerifyData == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->VerifyData(alias, flags, inData, inDataLength, inoutSign, inoutSignLength, outData, outDataLen, outVerifyInfo, outVerifyInfoLen, inCertID, outCert, outCertLength);
}

static unsigned long bridge_uverify_data(void *funcsPtr, char *alias, int flags, char *inData, int inDataLength, unsigned char *inOutSign, int inOutSignLength, char *outData, int *outDataLen, char *outVerifyInfo, int *outVerifyInfoLen, int inCertID, char *outCert, int *outCertLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->UVerifyData == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->UVerifyData(alias, flags, inData, inDataLength, inOutSign, inOutSignLength, outData, outDataLen, outVerifyInfo, outVerifyInfoLen, inCertID, outCert, outCertLength);
}
*/
import "C"

import "runtime"

func (h *linuxDriver) VerifyData(call VerifyDataCall) (VerifyResult, error) {
	return h.verifyData(call, false)
}

func (h *linuxDriver) UVerifyData(call VerifyDataCall) (VerifyResult, error) {
	return h.verifyData(call, true)
}

func (h *linuxDriver) verifyData(call VerifyDataCall, universal bool) (VerifyResult, error) {
	alias, freeAlias, err := cString(call.Alias)
	if err != nil {
		return VerifyResult{}, err
	}
	defer freeAlias()
	data, dataLen, err := inputBytes(call.Data)
	if err != nil {
		return VerifyResult{}, err
	}
	signature, signatureLen, err := inputBytes(call.Signature)
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

	dataOutLen := C.int(call.DataCapacity)
	infoLen := C.int(call.InfoCapacity)
	certLen := C.int(call.CertCapacity)

	var code C.ulong
	if universal {
		code = C.bridge_uverify_data(
			h.funcs,
			alias,
			C.int(call.Flags),
			charPtr(data),
			dataLen,
			ucharPtr(signature),
			signatureLen,
			charPtr(dataBuf),
			&dataOutLen,
			charPtr(infoBuf),
			&infoLen,
			C.int(call.CertID),
			charPtr(certBuf),
			&certLen,
		)
	} else {
		code = C.bridge_verify_data(
			h.funcs,
			alias,
			C.int(call.Flags),
			charPtr(data),
			dataLen,
			ucharPtr(signature),
			signatureLen,
			charPtr(dataBuf),
			&dataOutLen,
			charPtr(infoBuf),
			&infoLen,
			C.int(call.CertID),
			charPtr(certBuf),
			&certLen,
		)
	}
	runtime.KeepAlive(data)
	runtime.KeepAlive(signature)
	runtime.KeepAlive(dataBuf)
	runtime.KeepAlive(infoBuf)
	runtime.KeepAlive(certBuf)

	return VerifyResult{
		Code:    uint64(code),
		Data:    boundedBytes(dataBuf, int(dataOutLen)),
		DataLen: int(dataOutLen),
		Info:    boundedBytes(infoBuf, int(infoLen)),
		InfoLen: int(infoLen),
		Cert:    boundedBytes(certBuf, int(certLen)),
		CertLen: int(certLen),
	}, nil
}
