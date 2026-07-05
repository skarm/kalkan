//go:build linux && cgo

package kalkancrypt

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include "KalkanCrypt.h"

// KC_GetFunctionList and KC_InternalClearError are exported symbols, not fields
// of stKCFunctionsType. These wrappers let Go call those symbols after dlsym.
typedef int (*kc_get_function_list_fn)(stKCFunctionsType **);
typedef void (*kc_internal_clear_error_fn)(void);

static int bridge_get_function_list(void *symbol, stKCFunctionsType **out) {
    if (symbol == NULL || out == NULL) return -1;
    *out = NULL;
    return ((kc_get_function_list_fn)symbol)(out);
}

static void bridge_internal_clear_error(void *symbol) {
    if (symbol != NULL) ((kc_internal_clear_error_fn)symbol)();
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

const driverAvailable = true

// linuxDriver owns the Linux dlopen handle and the KC_GetFunctionList table.
type linuxDriver struct {
	handle     unsafe.Pointer
	funcs      unsafe.Pointer
	clearError unsafe.Pointer
}

func openDriver(path string) (driver, error) {
	cLibrary := C.CString(path)
	defer C.free(unsafe.Pointer(cLibrary))

	C.dlerror()
	handle := C.dlopen(cLibrary, C.RTLD_LAZY|C.RTLD_LOCAL)
	if handle == nil {
		return nil, errors.New(dlerrorString("dlopen failed"))
	}

	getListSymbol, err := dlsym(handle, "KC_GetFunctionList")
	if err != nil {
		C.dlclose(handle)
		return nil, err
	}

	var funcs *C.stKCFunctionsType
	rc := C.bridge_get_function_list(getListSymbol, &funcs)
	if rc != 0 {
		C.dlclose(handle)
		return nil, fmt.Errorf("KC_GetFunctionList failed with code %d", int(rc))
	}
	if funcs == nil {
		C.dlclose(handle)
		return nil, errors.New("KC_GetFunctionList returned a nil function table")
	}

	clearSymbol, _ := dlsym(handle, "KC_InternalClearError")

	return &linuxDriver{handle: handle, funcs: unsafe.Pointer(funcs), clearError: clearSymbol}, nil
}

func (h *linuxDriver) Close() error {
	if h == nil || h.handle == nil {
		return nil
	}

	handle := h.handle
	h.handle = nil
	h.funcs = nil
	h.clearError = nil

	C.dlerror()
	if rc := C.dlclose(handle); rc != 0 {
		return fmt.Errorf("dlclose failed: %s", dlerrorString("unknown dlclose error"))
	}

	return nil
}

func (h *linuxDriver) ClearError() {
	if h != nil && h.handle != nil && h.clearError != nil {
		C.bridge_internal_clear_error(h.clearError)
	}
}

func dlsym(handle unsafe.Pointer, name string) (unsafe.Pointer, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	C.dlerror()
	symbol := C.dlsym(handle, cName)
	if errMsg := C.dlerror(); errMsg != nil {
		return nil, fmt.Errorf("dlsym %s failed: %s", name, C.GoString(errMsg))
	}
	if symbol == nil {
		return nil, fmt.Errorf("dlsym %s returned nil", name)
	}

	return symbol, nil
}

func dlerrorString(fallback string) string {
	if errMsg := C.dlerror(); errMsg != nil {
		return C.GoString(errMsg)
	}

	return fallback
}
