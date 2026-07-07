//go:build windows && amd64

package ckalkan_test

import (
	"crypto/sha256"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestWindowsRealDLLCyrillicInputsSmoke(t *testing.T) {
	client := newRealClient(t)

	code, message := client.GetLastErrorString()
	if message == "" && code != ckalkan.ErrorOK {
		t.Fatalf("GetLastErrorString returned empty message for %s", code.Hex())
	}

	hash, err := client.HashData(ckalkan.SHA256, 0, []byte("abc"))
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}
	want := sha256.Sum256([]byte("abc"))
	if string(hash) != string(want[:]) {
		t.Fatalf("HashData returned %x, want %x", hash, want)
	}

	if err := client.SetTSAURL("http://localhost/тса"); err != nil {
		t.Fatalf("SetTSAURL with Cyrillic path segment failed: %v", err)
	}

	err = client.LoadKeyStore(ckalkan.StorePKCS12, "пароль", `C:\kalkan-no-such\ключ.p12`, "алиас")
	if err == nil {
		t.Log("LoadKeyStore with Cyrillic path/password/alias unexpectedly succeeded")
		return
	}

	requireKalkanError(t, "LoadKeyStore(cyrillic path/password/alias)", err)
}
