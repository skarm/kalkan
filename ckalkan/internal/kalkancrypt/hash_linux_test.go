//go:build linux && cgo

package kalkancrypt_test

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestContextHashDataSHA256(t *testing.T) {
	ctx := openContext(t)

	hashResult, err := ctx.HashData("sha256", 0, []byte("abc"), 128)
	digest := requireBufferOK(t, "HashData", hashResult, err)
	want := sha256.Sum256([]byte("abc"))
	if !bytes.Equal(digest, want[:]) {
		t.Fatalf("HashData(sha256, abc) = %x, want %x", digest, want)
	}
}
