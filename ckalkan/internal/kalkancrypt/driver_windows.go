//go:build windows && amd64

package kalkancrypt

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const driverAvailable = true

const (
	// LOAD_LIBRARY_SEARCH_* values from libloaderapi.h.
	loadLibrarySearchDLLLoadDir  = 0x00000100
	loadLibrarySearchDefaultDirs = 0x00001000
	dependencySearchFlags        = loadLibrarySearchDLLLoadDir | loadLibrarySearchDefaultDirs
)

//nolint:gochecknoglobals // Process-wide Windows API procedure handle.
var loadLibraryExW = syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryExW")

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
	return openDriverWithLoader(path, loadLibraryEx)
}

func openDriverWithLoader(path string, load func(string, uintptr) (*syscall.DLL, error)) (driver, error) {
	dll, err := load(path, dependencySearchFlags)
	if err != nil {
		return nil, fmt.Errorf("LoadLibraryExW %s failed: %w", path, err)
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

func loadLibraryEx(path string, flags uintptr) (*syscall.DLL, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, _, callErr := loadLibraryExW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		flags,
	)
	runtime.KeepAlive(pathPtr)

	if handle == 0 {
		if errors.Is(callErr, syscall.Errno(0)) {
			callErr = errors.New("LoadLibraryExW returned a null handle")
		}

		return nil, callErr
	}

	return &syscall.DLL{Name: path, Handle: syscall.Handle(handle)}, nil
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
