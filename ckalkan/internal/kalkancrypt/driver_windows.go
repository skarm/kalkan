//go:build windows && amd64

package kalkancrypt

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const driverAvailable = true

type windowsDriver struct {
	dll        *syscall.DLL
	funcs      *kcFunctionList
	clearError uintptr
}

// kcFunctionList mirrors stKCFunctionsType from KalkanCrypt.h. Windows uses the
// same KC_GetFunctionList table layout; each field is a native function pointer.
type kcFunctionList struct {
	init                      uintptr
	getTokens                 uintptr
	getCertificatesList       uintptr
	loadKeyStore              uintptr
	x509LoadCertificateFile   uintptr
	x509LoadCertificateBuffer uintptr
	x509ExportCertStore       uintptr
	x509CertificateGetInfo    uintptr
	x509ValidateCertificate   uintptr
	hashData                  uintptr
	signHash                  uintptr
	signData                  uintptr
	signXML                   uintptr
	verifyData                uintptr
	verifyXML                 uintptr
	getCertFromXML            uintptr
	getSigAlgFromXML          uintptr
	getLastError              uintptr
	getLastErrorString        uintptr
	xmlFinalize               uintptr
	finalize                  uintptr
	tsaSetURL                 uintptr
	getTimeFromSig            uintptr
	setProxy                  uintptr
	getCertFromCMS            uintptr
	signWSSE                  uintptr
	zipConVerify              uintptr
	zipConSign                uintptr
	getCertFromZipFile        uintptr
	uverifyData               uintptr
	initDebug                 uintptr
}

func openDriver(path string) (driver, error) {
	dll, err := syscall.LoadDLL(path)
	if err != nil {
		return nil, fmt.Errorf("LoadLibrary %s failed: %w", path, err)
	}

	getList, err := dll.FindProc("KC_GetFunctionList")
	if err != nil {
		_ = dll.Release()

		return nil, fmt.Errorf("GetProcAddress KC_GetFunctionList failed: %w", err)
	}

	var funcs *kcFunctionList
	rc, _, callErr := getList.Call(uintptr(unsafe.Pointer(&funcs)))
	if rc != 0 {
		_ = dll.Release()

		if callErr != syscall.Errno(0) {
			return nil, fmt.Errorf("KC_GetFunctionList failed with code %d: %w", int32(rc), callErr)
		}

		return nil, fmt.Errorf("KC_GetFunctionList failed with code %d", int32(rc))
	}
	if funcs == nil {
		_ = dll.Release()

		return nil, errors.New("KC_GetFunctionList returned a nil function table")
	}

	var clearError uintptr
	if proc, err := dll.FindProc("KC_InternalClearError"); err == nil {
		clearError = proc.Addr()
	}

	return &windowsDriver{dll: dll, funcs: funcs, clearError: clearError}, nil
}

func (h *windowsDriver) Close() error {
	if h == nil || h.dll == nil {
		return nil
	}

	dll := h.dll
	h.dll = nil
	h.funcs = nil
	h.clearError = 0

	return dll.Release()
}

func (h *windowsDriver) ClearError() {
	callWindowsVoid(h.clearError)
}

func callWindowsStatus(fn uintptr, args ...uintptr) uint64 {
	if fn == 0 {
		return errorLibraryNotInitialized
	}

	code, _, _ := syscall.SyscallN(fn, args...)

	return uint64(uint32(code))
}

func callWindowsVoid(fn uintptr, args ...uintptr) {
	if fn != 0 {
		_, _, _ = syscall.SyscallN(fn, args...)
	}
}
