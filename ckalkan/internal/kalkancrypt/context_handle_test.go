package kalkancrypt

import "testing"

func TestContextDelegatesAndClosesDriver(t *testing.T) {
	d := &fakeDriver{}
	ctx := &Context{driver: d}

	got, err := ctx.HashData("sha256", 7, []byte("abc"), 128)
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
