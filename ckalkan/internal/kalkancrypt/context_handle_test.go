package kalkancrypt

import (
	"reflect"
	"testing"
)

func TestContextDelegatesAndClosesDriver(t *testing.T) {
	d := &fakeDriver{}
	ctx := &Context{driver: d}

	got, err := ctx.HashData(HashDataCall{
		Algorithm: "sha256",
		Flags:     7,
		Data:      []byte("abc"),
		Capacity:  128,
	})
	if err != nil {
		t.Fatalf("HashData returned error: %v", err)
	}
	if string(got.Data) != "hash:sha256:7:abc:128" {
		t.Fatalf("HashData data = %q", got.Data)
	}
	if d.hashCalls != 1 {
		t.Fatalf("hashCalls = %d, want 1", d.hashCalls)
	}

	if err := ctx.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if d.closeCalls != 1 {
		t.Fatalf("closeCalls = %d, want 1", d.closeCalls)
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
	if d.closeCalls != 1 {
		t.Fatalf("second Close called driver again: %d", d.closeCalls)
	}
}

func TestContextDelegatesCallParametersToDriver(t *testing.T) {
	d := &fakeDriver{}
	ctx := &Context{driver: d}

	signHash := SignHashCall{Alias: "hash-alias", Flags: 1, Hash: []byte("hash"), Capacity: 11}
	if _, err := ctx.SignHash(signHash); err != nil {
		t.Fatalf("SignHash returned error: %v", err)
	}
	if !reflect.DeepEqual(d.signHashCall, signHash) {
		t.Fatalf("SignHash driver call = %#v, want %#v", d.signHashCall, signHash)
	}

	signData := SignDataCall{Alias: "data-alias", Flags: 2, Data: []byte("data"), Signature: []byte("signature"), Capacity: 22}
	if _, err := ctx.SignData(signData); err != nil {
		t.Fatalf("SignData returned error: %v", err)
	}
	if !reflect.DeepEqual(d.signDataCall, signData) {
		t.Fatalf("SignData driver call = %#v, want %#v", d.signDataCall, signData)
	}

	verifyXML := VerifyXMLCall{Alias: "xml-alias", Flags: 3, XML: []byte("<xml/>"), Capacity: 33}
	if _, err := ctx.VerifyXML(verifyXML); err != nil {
		t.Fatalf("VerifyXML returned error: %v", err)
	}
	if !reflect.DeepEqual(d.verifyXMLCall, verifyXML) {
		t.Fatalf("VerifyXML driver call = %#v, want %#v", d.verifyXMLCall, verifyXML)
	}

	certFromCMS := GetCertFromCMSCall{CMS: []byte("cms"), SignID: 4, Flags: 5, Capacity: 44}
	if _, err := ctx.GetCertFromCMS(certFromCMS); err != nil {
		t.Fatalf("GetCertFromCMS returned error: %v", err)
	}
	if !reflect.DeepEqual(d.getCertFromCMSCall, certFromCMS) {
		t.Fatalf("GetCertFromCMS driver call = %#v, want %#v", d.getCertFromCMSCall, certFromCMS)
	}

	certFromZip := GetCertFromZipFileCall{ZipFile: "signed.zip", Flags: 6, SignID: 7, Capacity: 55}
	if _, err := ctx.GetCertFromZipFile(certFromZip); err != nil {
		t.Fatalf("GetCertFromZipFile returned error: %v", err)
	}
	if !reflect.DeepEqual(d.getCertFromZipFileCall, certFromZip) {
		t.Fatalf("GetCertFromZipFile driver call = %#v, want %#v", d.getCertFromZipFileCall, certFromZip)
	}
}
