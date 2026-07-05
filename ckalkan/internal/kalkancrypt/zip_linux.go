//go:build linux && cgo

package kalkancrypt

/*
#include "KalkanCrypt.h"

static unsigned long bridge_zip_con_verify(void *funcsPtr, char *inZipFile, int flags, char *outVerifyInfo, int *outVerifyInfoLen) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->ZipConVerify == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->ZipConVerify(inZipFile, flags, outVerifyInfo, outVerifyInfoLen);
}

static unsigned long bridge_zip_con_sign(void *funcsPtr, char *alias, const char *filePath, const char *name, const char *outDir, int flags) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->ZipConSign == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->ZipConSign(alias, filePath, name, outDir, flags);
}

static unsigned long bridge_get_cert_from_zip_file(void *funcsPtr, char *inZipFile, int flags, int inSignID, char *outCert, int *outCertLength) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_getCertFromZipFile == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_getCertFromZipFile(inZipFile, flags, inSignID, outCert, outCertLength);
}
*/
import "C"

import "runtime"

func (h *linuxDriver) ZipConVerify(zipFile string, flags, capacity int) (BufferResult, error) {
	inZip, freeInZip, err := cString(zipFile)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeInZip()

	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(capacity)
	code := C.bridge_zip_con_verify(h.funcs, inZip, C.int(flags), charPtr(buf), &outLen)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}

func (h *linuxDriver) ZipConSign(call ZipConSignCall) uint64 {
	alias, freeAlias, err := cString(call.Alias)
	if err != nil {
		return errorParam
	}
	defer freeAlias()
	filePath, freeFilePath, err := cString(call.FilePath)
	if err != nil {
		return errorParam
	}
	defer freeFilePath()
	name, freeName, err := cString(call.Name)
	if err != nil {
		return errorParam
	}
	defer freeName()
	outDir, freeOutDir, err := cString(call.OutDir)
	if err != nil {
		return errorParam
	}
	defer freeOutDir()

	return uint64(C.bridge_zip_con_sign(h.funcs, alias, filePath, name, outDir, C.int(call.Flags)))
}

func (h *linuxDriver) GetCertFromZipFile(zipFile string, flags, signID, capacity int) (BufferResult, error) {
	inZip, freeInZip, err := cString(zipFile)
	if err != nil {
		return BufferResult{}, err
	}
	defer freeInZip()

	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := C.int(capacity)
	code := C.bridge_get_cert_from_zip_file(h.funcs, inZip, C.int(flags), C.int(signID), charPtr(buf), &outLen)
	runtime.KeepAlive(buf)

	return BufferResult{Code: uint64(code), Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
