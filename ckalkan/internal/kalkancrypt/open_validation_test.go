package kalkancrypt_test

import (
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestOpenRejectsEmbeddedNULBeforeNativeLoad(t *testing.T) {
	ctx, err := kalkancrypt.Open("/tmp/lib.so\x00suffix")
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		if ctx != nil {
			_ = ctx.Close()
		}
		t.Fatalf("Open with embedded NUL returned ctx=%#v err=%v, want NUL rejection", ctx, err)
	}
	if ctx != nil {
		t.Fatalf("Open returned context %#v with error %v", ctx, err)
	}
}
