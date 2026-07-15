//go:build windows && amd64

package kalkancrypt

import (
	"bytes"
	"errors"
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
