//go:build linux && cgo

package kalkancrypt

/*
#include "KalkanCrypt.h"

static unsigned long bridge_verify_xml(void *funcsPtr, char *alias, int flags, char *inData, int inDataLength, char *outVerifyInfo, int *outVerifyInfoLen) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->VerifyXML == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->VerifyXML(alias, flags, inData, inDataLength, outVerifyInfo, outVerifyInfoLen);
}

static unsigned long bridge_get_cert_from_xml(void *funcsPtr, const char *inXML, int inXMLLength, int inSignID, char *outCert, int *outCertLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_getCertFromXML == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_getCertFromXML(inXML, inXMLLength, inSignID, outCert, outCertLength);
}

static unsigned long bridge_get_sig_alg_from_xml(void *funcsPtr, const char *xml_in, int xml_in_size, char *retSigAlg, int *retLen) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_getSigAlgFromXML == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_getSigAlgFromXML(xml_in, xml_in_size, retSigAlg, retLen);
}
*/
import "C"

import "runtime"

func (h *linuxDriver) VerifyXML(alias string, flags int, xml []byte, capacity int) (BufferResult, error) {
	cAlias, freeAlias, err := cString(alias)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeAlias()

	in, inLen, err := inputBytes(xml)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(capacity)
	code := C.bridge_verify_xml(h.funcs, cAlias, C.int(flags), charPtr(in), inLen, charPtr(buf), &outLen)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *linuxDriver) GetCertFromXML(xml []byte, signID, capacity int) (BufferResult, error) {
	in, inLen, err := inputBytes(xml)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(capacity)
	code := C.bridge_get_cert_from_xml(h.funcs, charPtr(in), inLen, C.int(signID), charPtr(buf), &outLen)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *linuxDriver) GetSigAlgFromXML(xml []byte, capacity int) (BufferResult, error) {
	in, inLen, err := inputBytes(xml)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(capacity)
	code := C.bridge_get_sig_alg_from_xml(h.funcs, charPtr(in), inLen, charPtr(buf), &outLen)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
