package ckalkan

import (
	"errors"
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestClosedClientMethodsReturnErrClosed(t *testing.T) {
	if !kalkancrypt.Available() {
		t.Skip("ErrClosed is observable only when the native loader is available")
	}

	cli := &Client{closed: true}

	if err := cli.Init(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Init on closed client = %v, want ErrClosed", err)
	}
	if _, err := cli.HashData(SHA256, 0, []byte("abc")); !errors.Is(err, ErrClosed) {
		t.Fatalf("HashData on closed client = %v, want ErrClosed", err)
	}
	if _, err := cli.VerifyData(VerifyDataRequest{Flags: SignCMS}); !errors.Is(err, ErrClosed) {
		t.Fatalf("VerifyData on closed client = %v, want ErrClosed", err)
	}
}
