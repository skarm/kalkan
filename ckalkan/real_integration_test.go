package ckalkan_test

import (
	"crypto/sha256"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestRealKalkanCryptSmoke(t *testing.T) {
	cli := newRealClient(t, ckalkan.WithMaxBufferSize(1024))

	hash, err := cli.HashData(ckalkan.SHA256, 0, []byte("abc"))
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}
	want := sha256.Sum256([]byte("abc"))
	if string(hash) != string(want[:]) {
		t.Fatalf("HashData returned %x, want %x", hash, want)
	}

	if err := cli.LoadKeyStore(ckalkan.StorePKCS12, "bad-password", "/tmp/ckalkan-no-such-key.p12", ""); err == nil {
		t.Fatal("LoadKeyStore with a missing file unexpectedly succeeded")
	} else if _, ok := ckalkan.ErrorCodeOf(err); !ok {
		t.Fatalf("LoadKeyStore returned a non-Kalkan error: %T %v", err, err)
	}
}
