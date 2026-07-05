//go:build linux && cgo

package kalkancrypt

/*
#include "KalkanCrypt.h"

static unsigned long bridge_tsa_set_url(void *funcsPtr, char *tsaurl) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_TSASetUrl == NULL) return KCR_LIBRARYNOTINITIALIZED;
    funcs->KC_TSASetUrl(tsaurl);
    return KCR_OK;
}

static unsigned long bridge_set_proxy(void *funcsPtr, int flags, char *inProxyAddr, char *inProxyPort, char *inUser, char *inPass) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_SetProxy == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_SetProxy(flags, inProxyAddr, inProxyPort, inUser, inPass);
}
*/
import "C"

func (h *linuxDriver) SetTSAURL(tsaURL string) uint64 {
	url, freeURL, err := cString(tsaURL)
	if err != nil {
		return errorParam
	}
	defer freeURL()

	return uint64(C.bridge_tsa_set_url(h.funcs, url))
}

func (h *linuxDriver) SetProxy(call ProxyCall) uint64 {
	addr, freeAddr, err := cString(call.Address)
	if err != nil {
		return errorParam
	}
	defer freeAddr()
	port, freePort, err := cString(call.Port)
	if err != nil {
		return errorParam
	}
	defer freePort()
	user, freeUser, err := cString(call.User)
	if err != nil {
		return errorParam
	}
	defer freeUser()
	pass, freePass, err := cString(call.Password)
	if err != nil {
		return errorParam
	}
	defer freePass()

	return uint64(C.bridge_set_proxy(h.funcs, C.int(call.Flags), addr, port, user, pass))
}
