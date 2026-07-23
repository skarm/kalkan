//go:build linux && cgo

package kalkancrypt

/*
#include "KalkanCrypt.h"

static unsigned long bridge_sign_hash(void *funcsPtr, char *alias, int flags, char *inHash, int inHashLength, unsigned char *outSign, int *outSignLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->SignHash == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->SignHash(alias, flags, inHash, inHashLength, outSign, outSignLength);
}

static unsigned long bridge_sign_data(void *funcsPtr, char *alias, int flags, char *inData, int inDataLength, unsigned char *inSign, int inSignLen, unsigned char *outSign, int *outSignLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->SignData == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->SignData(alias, flags, inData, inDataLength, inSign, inSignLen, outSign, outSignLength);
}

static unsigned long bridge_sign_xml(void *funcsPtr, char *alias, int flags, char *inData, int inDataLength, unsigned char *outSign, int *outSignLength, char *signNodeId, char *parentSignNode, char *parentNameSpace) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->SignXML == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->SignXML(alias, flags, inData, inDataLength, outSign, outSignLength, signNodeId, parentSignNode, parentNameSpace);
}

static unsigned long bridge_sign_wsse(void *funcsPtr, char *alias, unsigned long flags, char *inData, int inDataLength, unsigned char *outSign, int *outSignLength, char *signNodeId) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->SignWSSE == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->SignWSSE(alias, flags, inData, inDataLength, outSign, outSignLength, signNodeId);
}
*/
import "C"

import "runtime"

func (h *linuxDriver) SignHash(call SignHashCall) (BufferResult, error) {
	cAlias, freeAlias, err := cString(call.Alias)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeAlias()

	in, inLen, err := inputBytes(call.Hash)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(call.Capacity)
	code := C.bridge_sign_hash(h.funcs, cAlias, C.int(call.Flags), charPtr(in), inLen, ucharPtr(buf), &outLen)
	runtime.KeepAlive(in)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *linuxDriver) SignData(call SignDataCall) (BufferResult, error) {
	cAlias, freeAlias, err := cString(call.Alias)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeAlias()

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

	outLen := C.int(call.Capacity)
	code := C.bridge_sign_data(h.funcs, cAlias, C.int(call.Flags), charPtr(inData), inDataLen, ucharPtr(inSig), inSigLen, ucharPtr(buf), &outLen)
	runtime.KeepAlive(inData)
	runtime.KeepAlive(inSig)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *linuxDriver) SignXML(call SignXMLCall) (BufferResult, error) {
	alias, freeAlias, err := cString(call.Alias)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeAlias()
	xml, xmlLen, err := inputBytes(call.XML)
	if err != nil {
		return BufferResult{}, err
	}
	signNodeID, freeSignNodeID, err := cString(call.SignNodeID)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeSignNodeID()
	parentSignNode, freeParentSignNode, err := cString(call.ParentSignNode)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeParentSignNode()
	parentNamespace, freeParentNamespace, err := cString(call.ParentNamespace)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeParentNamespace()

	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(call.Capacity)
	code := C.bridge_sign_xml(
		h.funcs,
		alias,
		C.int(call.Flags),
		charPtr(xml),
		xmlLen,
		ucharPtr(buf),
		&outLen,
		signNodeID,
		parentSignNode,
		parentNamespace,
	)
	runtime.KeepAlive(xml)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *linuxDriver) SignWSSE(call SignWSSECall) (BufferResult, error) {
	alias, freeAlias, err := cString(call.Alias)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeAlias()
	xml, xmlLen, err := inputBytes(call.XML)
	if err != nil {
		return BufferResult{}, err
	}
	signNodeID, freeSignNodeID, err := cString(call.SignNodeID)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeSignNodeID()

	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(call.Capacity)
	code := C.bridge_sign_wsse(h.funcs, alias, C.ulong(call.Flags), charPtr(xml), xmlLen, ucharPtr(buf), &outLen, signNodeID)
	runtime.KeepAlive(xml)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
