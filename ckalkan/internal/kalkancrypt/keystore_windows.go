//go:build windows && amd64

package kalkancrypt

import "runtime"

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
		bytesPtr(cPassword),
		intArg(len(password)),
		bytesPtr(cContainer),
		intArg(len(container)),
		bytesPtr(cAlias),
	)
	runtime.KeepAlive(cPassword)
	runtime.KeepAlive(cContainer)
	runtime.KeepAlive(cAlias)

	return code
}
