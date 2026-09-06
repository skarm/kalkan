//go:build windows && amd64

package kalkancrypt

import (
	"bytes"
	"errors"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func TestFunctionListLayout(t *testing.T) {
	var funcs kcFunctionList
	layout := []struct {
		name   string
		offset uintptr
	}{
		{name: "init", offset: unsafe.Offsetof(funcs.init)},
		{name: "getTokens", offset: unsafe.Offsetof(funcs.getTokens)},
		{name: "getCertificatesList", offset: unsafe.Offsetof(funcs.getCertificatesList)},
		{name: "loadKeyStore", offset: unsafe.Offsetof(funcs.loadKeyStore)},
		{name: "x509LoadCertificateFile", offset: unsafe.Offsetof(funcs.x509LoadCertificateFile)},
		{name: "x509LoadCertificateBuffer", offset: unsafe.Offsetof(funcs.x509LoadCertificateBuffer)},
		{name: "x509ExportCertStore", offset: unsafe.Offsetof(funcs.x509ExportCertStore)},
		{name: "x509CertificateGetInfo", offset: unsafe.Offsetof(funcs.x509CertificateGetInfo)},
		{name: "x509ValidateCertificate", offset: unsafe.Offsetof(funcs.x509ValidateCertificate)},
		{name: "hashData", offset: unsafe.Offsetof(funcs.hashData)},
		{name: "signHash", offset: unsafe.Offsetof(funcs.signHash)},
		{name: "signData", offset: unsafe.Offsetof(funcs.signData)},
		{name: "signXML", offset: unsafe.Offsetof(funcs.signXML)},
		{name: "verifyData", offset: unsafe.Offsetof(funcs.verifyData)},
		{name: "verifyXML", offset: unsafe.Offsetof(funcs.verifyXML)},
		{name: "getCertFromXML", offset: unsafe.Offsetof(funcs.getCertFromXML)},
		{name: "getSigAlgFromXML", offset: unsafe.Offsetof(funcs.getSigAlgFromXML)},
		{name: "getLastError", offset: unsafe.Offsetof(funcs.getLastError)},
		{name: "getLastErrorString", offset: unsafe.Offsetof(funcs.getLastErrorString)},
		{name: "xmlFinalize", offset: unsafe.Offsetof(funcs.xmlFinalize)},
		{name: "finalize", offset: unsafe.Offsetof(funcs.finalize)},
		{name: "tsaSetURL", offset: unsafe.Offsetof(funcs.tsaSetURL)},
		{name: "getTimeFromSig", offset: unsafe.Offsetof(funcs.getTimeFromSig)},
		{name: "setProxy", offset: unsafe.Offsetof(funcs.setProxy)},
		{name: "getCertFromCMS", offset: unsafe.Offsetof(funcs.getCertFromCMS)},
		{name: "signWSSE", offset: unsafe.Offsetof(funcs.signWSSE)},
		{name: "zipConVerify", offset: unsafe.Offsetof(funcs.zipConVerify)},
		{name: "zipConSign", offset: unsafe.Offsetof(funcs.zipConSign)},
		{name: "getCertFromZipFile", offset: unsafe.Offsetof(funcs.getCertFromZipFile)},
		{name: "uverifyData", offset: unsafe.Offsetof(funcs.uverifyData)},
		{name: "initDebug", offset: unsafe.Offsetof(funcs.initDebug)},
	}

	const fieldCount = 31
	if len(layout) != fieldCount {
		t.Fatalf("kcFunctionList field count = %d, want %d", len(layout), fieldCount)
	}

	pointerSize := unsafe.Sizeof(uintptr(0))
	for index, field := range layout {
		if want := uintptr(index) * pointerSize; field.offset != want {
			t.Fatalf("kcFunctionList.%s offset = %d, want %d", field.name, field.offset, want)
		}
	}

	if got, want := unsafe.Sizeof(funcs), uintptr(fieldCount)*pointerSize; got != want {
		t.Fatalf("kcFunctionList size = %d, want %d", got, want)
	}
}

func TestOpenDriverRejectsMissingDLL(t *testing.T) {
	if _, err := openDriver(`Z:\kalkan-no-such\KalkanCrypt.dll`); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("openDriver missing DLL error = %v, want native load error", err)
	}
}

func TestCallWindowsStatusRejectsMissingFunction(t *testing.T) {
	if got := callWindowsStatus(0); got != errorLibraryNotInitialized {
		t.Fatalf("callWindowsStatus(0) = %#x, want %#x", got, uint64(errorLibraryNotInitialized))
	}
}

func TestWindowsCertificateValidationPreservesNativePointers(t *testing.T) {
	// Enter Go through a native callback and grow its stack before writing both
	// output lengths. This exercises the actual syscall wrapper without the SDK.
	var calls int
	fn := syscall.NewCallback(func(cert *byte, certLen uintptr, mode uintptr, path *byte, checkTime uintptr,
		info *byte, infoLen *int32, flags uintptr, ocsp *byte, ocspLen *int32,
	) uintptr {
		calls++
		growWindowsCallbackStack(64)
		runtime.GC()
		if cert == nil || *cert != 0x30 || certLen != 2 || mode != 7 || path == nil || *path != 'p' || checkTime != 123 || flags != 9 {
			t.Error("native callback received incorrect input arguments")
			return uintptr(errorParam)
		}
		if infoLen == nil || ocspLen == nil || *infoLen != 32 || *ocspLen != 16 {
			t.Error("native callback received incorrect output capacities")
			return uintptr(errorParam)
		}
		copy(unsafe.Slice(info, 3), "ok!")
		copy(unsafe.Slice(ocsp, 4), []byte{1, 0, 2, 0})
		*infoLen, *ocspLen = 3, 4
		return 0
	})
	driver := &windowsDriver{funcs: &kcFunctionList{x509ValidateCertificate: fn}}
	result, err := driver.X509ValidateCertificate(ValidateCertificateCall{
		Certificate: []byte{0x30, 0}, ValidationType: 7, ValidationPath: "path", CheckTimeUnix: 123,
		Flags: 9, InfoCapacity: 32, OCSPCapacity: 16,
	})
	if err != nil || result.Code != 0 || calls != 1 {
		t.Fatalf("native call: result=%+v, calls=%d, err=%v", result, calls, err)
	}
	if result.InfoLen != 3 || result.OCSPLen != 4 || string(result.Info) != "ok!" || !bytes.Equal(result.OCSP, []byte{1, 0, 2, 0}) {
		t.Fatalf("native outputs were not preserved: %+v", result)
	}
}

func TestWindowsCMSExtractionKeepsBinaryInputWithInFile(t *testing.T) {
	want := []byte{0x30, 0, 1}
	var calls int
	fn := syscall.NewCallback(func(cms *byte, cmsLen uintptr, signID uintptr, flags uintptr, out *byte, outLen *int32) uintptr {
		calls++
		if cms == nil || !bytes.Equal(unsafe.Slice(cms, cmsLen), want) || flags != inFileFlag || signID != 1 {
			t.Error("native callback received incorrect CMS input")
			return uintptr(errorParam)
		}
		*out = 'c'
		*outLen = 1
		return 0
	})
	driver := &windowsDriver{funcs: &kcFunctionList{getCertFromCMS: fn}}
	result, err := driver.GetCertFromCMS(GetCertFromCMSCall{CMS: want, SignID: 1, Flags: inFileFlag, Capacity: 8})
	if err != nil || result.Code != 0 || string(result.Data) != "c" || calls != 1 {
		t.Fatalf("GetCertFromCMS = %+v, %v, calls = %d", result, err, calls)
	}
}

//go:noinline
func growWindowsCallbackStack(depth int) {
	var padding [8192]byte
	if depth > 0 {
		growWindowsCallbackStack(depth - 1)
	}
	runtime.KeepAlive(&padding)
}

func TestNarrowStringUsesUTF8(t *testing.T) {
	got, err := narrowString("ключ")
	if err != nil {
		t.Fatalf("narrowString returned error: %v", err)
	}
	want := append([]byte("ключ"), 0)
	if !bytes.Equal(got, want) {
		t.Fatalf("narrowString bytes = %v, want UTF-8 bytes %v", got, want)
	}
}

func TestNarrowStringRejectsNUL(t *testing.T) {
	if _, err := narrowString("bad\x00value"); err == nil {
		t.Fatal("narrowString unexpectedly accepted embedded NUL")
	}
}

func TestOpenDriverPassesSearchFlags(t *testing.T) {
	wantErr := errors.New("stop after load")
	var gotPath string
	var gotFlags uintptr

	_, err := openDriverWithLoader(`C:\Kalkan\KalkanCrypt.dll`, func(path string, flags uintptr) (*syscall.DLL, error) {
		gotPath = path
		gotFlags = flags

		return nil, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("openDriverWithLoader error = %v, want loader error", err)
	}
	if gotPath != `C:\Kalkan\KalkanCrypt.dll` {
		t.Fatalf("loader path = %q, want configured DLL path", gotPath)
	}
	if want := uintptr(0x00001100); gotFlags != want {
		t.Fatalf("loader flags = %#x, want %#x", gotFlags, want)
	}
}
