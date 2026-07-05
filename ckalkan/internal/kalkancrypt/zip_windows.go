//go:build windows && amd64

package kalkancrypt

import "runtime"

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
	code := callWindowsStatus(h.funcs.zipConVerify, bytesPtr(inZip), intArg(flags), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(inZip)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
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

	code := callWindowsStatus(h.funcs.zipConSign, bytesPtr(alias), bytesPtr(filePath), bytesPtr(name), bytesPtr(outDir), intArg(call.Flags))
	runtime.KeepAlive(alias)
	runtime.KeepAlive(filePath)
	runtime.KeepAlive(name)
	runtime.KeepAlive(outDir)

	return code
}

func (h *windowsDriver) GetCertFromZipFile(zipFile string, flags, signID, capacity int) (BufferResult, error) {
	inZip, err := narrowString(zipFile)
	if err != nil {
		return BufferResult{}, err
	}
	buf, err := outputBuffer(capacity)
	if err != nil {
		return BufferResult{}, err
	}

	outLen := int32(capacity)
	code := callWindowsStatus(h.funcs.getCertFromZipFile, bytesPtr(inZip), intArg(flags), intArg(signID), bytesPtr(buf), int32Ptr(&outLen))
	runtime.KeepAlive(inZip)
	runtime.KeepAlive(buf)

	return BufferResult{Code: code, Data: boundedBytes(buf, int(outLen)), OutLen: int(outLen)}, nil
}
