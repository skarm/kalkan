package ckalkan

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestNativeFlagConversionsValidateRange(t *testing.T) {
	if got, err := flagsToNativeInt(SignCMS | OutBase64); err != nil || got != int(SignCMS|OutBase64) {
		t.Fatalf("flagsToNativeInt(valid) = %d, %v", got, err)
	}
	if _, err := flagsToNativeInt(Flag(-1)); err == nil {
		t.Fatal("flagsToNativeInt accepted a negative mask")
	}
	if strconv.IntSize > 32 {
		tooLarge := int64(maxNativeCInt) + 1
		if _, err := flagsToNativeInt(Flag(tooLarge)); err == nil {
			t.Fatal("flagsToNativeInt accepted a mask that overflows C int")
		}
	}
	if got, err := flagsToNativeUnsignedLong(SignCMS | OutBase64); err != nil || got != uint64(SignCMS|OutBase64) {
		t.Fatalf("flagsToNativeUnsignedLong(valid) = %d, %v", got, err)
	}
	if _, err := flagsToNativeUnsignedLong(Flag(-1)); err == nil {
		t.Fatal("flagsToNativeUnsignedLong accepted a negative mask")
	}
	if strconv.IntSize > 32 {
		tooLarge := int64(maxNativeUnsignedLong) + 1
		if _, err := flagsToNativeUnsignedLong(Flag(tooLarge)); err == nil {
			t.Fatal("flagsToNativeUnsignedLong accepted a mask that overflows C unsigned long")
		}
	}
}

func TestNativeStoreConversionsValidateRange(t *testing.T) {
	if got, err := storeToNativeInt(StorePKCS12); err != nil || got != int(StorePKCS12) {
		t.Fatalf("storeToNativeInt(valid) = %d, %v", got, err)
	}
	if strconv.IntSize > 32 {
		if _, err := storeToNativeInt(Store(int64(maxNativeCInt) + 1)); err == nil {
			t.Fatal("storeToNativeInt accepted a value that overflows C int")
		}
	}
	if got, err := storeToNativeUnsignedLong(StoreKazToken); err != nil || got != uint64(StoreKazToken) {
		t.Fatalf("storeToNativeUnsignedLong(valid) = %d, %v", got, err)
	}
	if strconv.IntSize > 32 {
		if _, err := storeToNativeUnsignedLong(Store(int64(maxNativeUnsignedLong) + 1)); err == nil {
			t.Fatal("storeToNativeUnsignedLong accepted a value that overflows C unsigned long")
		}
	}
}

func TestSignDataUsesCallerInputs(t *testing.T) {
	originalData := []byte("original-data")
	originalSignature := []byte("original-signature")
	nativeEntered := make(chan struct{})
	releaseNative := make(chan struct{})
	dataSeen := make(chan []byte, 1)
	signatureSeen := make(chan []byte, 1)
	ctx := &fakeNativeContext{
		signDataFunc: func(call kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error) {
			close(nativeEntered)
			<-releaseNative
			dataSeen <- append([]byte(nil), call.Data...)
			signatureSeen <- append([]byte(nil), call.Signature...)
			return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
		},
	}
	cli := &Client{ctx: ctx, config: defaultConfig()}

	done := make(chan error, 1)
	go func() {
		_, err := cli.SignData(SignDataRequest{
			Alias:     "alias",
			Flags:     SignCMS,
			Data:      originalData,
			Signature: originalSignature,
		})
		done <- err
	}()

	<-nativeEntered
	copy(originalData, []byte("mutated!-data"))
	copy(originalSignature, []byte("mutated!-signature"))
	close(releaseNative)

	if err := <-done; err != nil {
		t.Fatalf("SignData returned error: %v", err)
	}
	if got := <-dataSeen; !bytes.Equal(got, []byte("mutated!-data")) {
		t.Fatalf("native data = %q, want caller data without cloning", got)
	}
	if got := <-signatureSeen; !bytes.Equal(got, []byte("mutated!-signature")) {
		t.Fatalf("native signature = %q, want caller signature without cloning", got)
	}
}

func TestZipConSignAcceptsEmptyStrings(t *testing.T) {
	nativeCalls := 0
	ctx := &fakeNativeContext{
		zipConSignFunc: func(call kalkancrypt.ZipConSignCall) uint64 {
			nativeCalls++

			return uint64(ErrorOK)
		},
	}
	cli := &Client{ctx: ctx, config: defaultConfig()}

	for _, req := range []ZipConSignRequest{
		{Name: "signed", OutDir: "/tmp"},
		{FilePath: "/tmp/input.zip", OutDir: "/tmp"},
		{FilePath: "/tmp/input.zip", Name: "signed"},
	} {
		err := cli.ZipConSign(req)
		if err != nil {
			t.Fatalf("ZipConSign(%+v) returned error: %v", req, err)
		}
	}
	if nativeCalls != 3 {
		t.Fatalf("ZipConSign native calls = %d, want 3", nativeCalls)
	}
}

func TestX509LoadCertificateFromBufferAcceptsEmptyInput(t *testing.T) {
	nativeCalls := 0
	ctx := &fakeNativeContext{
		x509LoadBufferFunc: func(cert []byte, format int) uint64 {
			nativeCalls++
			if cert != nil {
				t.Fatalf("native certificate = %v, want nil empty input", cert)
			}

			return uint64(ErrorOK)
		},
	}
	cli := &Client{ctx: ctx, config: defaultConfig()}

	if err := cli.X509LoadCertificateFromBuffer(nil, CertPEM); err != nil {
		t.Fatalf("X509LoadCertificateFromBuffer returned error: %v", err)
	}
	if nativeCalls != 1 {
		t.Fatalf("native calls = %d, want 1", nativeCalls)
	}
}
