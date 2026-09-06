//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"
)

func (h *windowsDriver) ZipConVerify(zipFile string, flags, capacity int) (BufferResult, error) {
	inZip, err := narrowString(zipFile)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity)
	code := callWindowsStatus(
		h.funcs.zipConVerify,
		uintptr(unsafe.Pointer(bytesPtr(inZip))),
		intArg(flags),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(inZip)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}

func (h *windowsDriver) ZipConSign(call ZipConSignCall) uint64 {
	alias, err := narrowString(call.Alias)
	if err != nil {
		return errorParam
	}
	filePath, err := narrowString(call.FilePath)
	if err != nil {
		return errorParam
	}
	name, err := narrowString(call.Name)
	if err != nil {
		return errorParam
	}
	outDir, err := narrowString(call.OutDir)
	if err != nil {
		return errorParam
	}

	code := callWindowsStatus(
		h.funcs.zipConSign,
		uintptr(unsafe.Pointer(bytesPtr(alias))),
		uintptr(unsafe.Pointer(bytesPtr(filePath))),
		uintptr(unsafe.Pointer(bytesPtr(name))),
		uintptr(unsafe.Pointer(bytesPtr(outDir))),
		intArg(call.Flags),
	)
	runtime.KeepAlive(alias)
	runtime.KeepAlive(filePath)
	runtime.KeepAlive(name)
	runtime.KeepAlive(outDir)

	return code
}

func (h *windowsDriver) GetCertFromZipFile(call GetCertFromZipFileCall) (BufferResult, error) {
	inZip, err := narrowString(call.ZipFile)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(call.Capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(call.Capacity)
	code := callWindowsStatus(
		h.funcs.getCertFromZipFile,
		uintptr(unsafe.Pointer(bytesPtr(inZip))),
		intArg(call.Flags),
		intArg(call.SignID),
		uintptr(unsafe.Pointer(bytesPtr(buf))),
		uintptr(unsafe.Pointer(&outLen)),
	)
	runtime.KeepAlive(inZip)
	runtime.KeepAlive(buf)

	return bufferResult(code, buf, int(outLen)), nil
}
