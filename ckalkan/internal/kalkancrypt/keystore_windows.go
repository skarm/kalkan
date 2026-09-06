//go:build windows && amd64

package kalkancrypt

import (
	"runtime"
	"unsafe"
)

func (h *windowsDriver) LoadKeyStore(storage int, password, container, alias string) uint64 {
	cPassword, err := narrowString(password)
	if err != nil {
		return errorParam
	}

	cContainer, err := narrowString(container)
	if err != nil {
		return errorParam
	}

	cAlias, err := narrowString(alias)
	if err != nil {
		return errorParam
	}

	code := callWindowsStatus(
		h.funcs.loadKeyStore,
		intArg(storage),
		uintptr(unsafe.Pointer(bytesPtr(cPassword))),
		intArg(len(password)),
		uintptr(unsafe.Pointer(bytesPtr(cContainer))),
		intArg(len(container)),
		uintptr(unsafe.Pointer(bytesPtr(cAlias))),
	)
	runtime.KeepAlive(cPassword)
	runtime.KeepAlive(cContainer)
	runtime.KeepAlive(cAlias)

	return code
}
