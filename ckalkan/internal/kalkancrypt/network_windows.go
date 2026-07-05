//go:build windows && amd64

package kalkancrypt

import "runtime"

func (h *windowsDriver) SetTSAURL(tsaURL string) uint64 {
	url, err := narrowString(tsaURL)
	if err != nil {
		return errorParam
	}
	if h.funcs.tsaSetURL == 0 {
		return errorLibraryNotInitialized
	}
	callWindowsVoid(h.funcs.tsaSetURL, bytesPtr(url))
	runtime.KeepAlive(url)

	return 0
}

func (h *windowsDriver) SetProxy(call ProxyCall) uint64 {
	addr, err := narrowString(call.Address)
	if err != nil {
		return errorParam
	}
	port, err := narrowString(call.Port)
	if err != nil {
		return errorParam
	}
	user, err := narrowString(call.User)
	if err != nil {
		return errorParam
	}
	pass, err := narrowString(call.Password)
	if err != nil {
		return errorParam
	}

	code := callWindowsStatus(h.funcs.setProxy, intArg(call.Flags), bytesPtr(addr), bytesPtr(port), bytesPtr(user), bytesPtr(pass))
	runtime.KeepAlive(addr)
	runtime.KeepAlive(port)
	runtime.KeepAlive(user)
	runtime.KeepAlive(pass)

	return code
}
