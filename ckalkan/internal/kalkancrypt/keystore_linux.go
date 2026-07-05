//go:build linux && cgo

package kalkancrypt

/*
#include "KalkanCrypt.h"

static unsigned long bridge_load_key_store(void *funcsPtr, int storage, char *password, int passLen, char *container, int containerLen, char *alias) {
    stKCFunctionsType *funcs = (stKCFunctionsType*)funcsPtr;
    if (funcs == NULL || funcs->KC_LoadKeyStore == NULL) return KCR_LIBRARYNOTINITIALIZED;
    return funcs->KC_LoadKeyStore(storage, password, passLen, container, containerLen, alias);
}
*/
import "C"

func (h *linuxDriver) LoadKeyStore(storage int, password, container, alias string) uint64 {
	cPassword, freePassword, err := cString(password)
	if err != nil {
		return errorParam
	}
	defer freePassword()
	cContainer, freeContainer, err := cString(container)
	if err != nil {
		return errorParam
	}
	defer freeContainer()
	cAlias, freeAlias, err := cString(alias)
	if err != nil {
		return errorParam
	}
	defer freeAlias()

	return uint64(C.bridge_load_key_store(
		h.funcs,
		C.int(storage),
		cPassword,
		C.int(len(password)),
		cContainer,
		C.int(len(container)),
		cAlias,
	))
}
