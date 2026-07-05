package ckalkan

import (
	"errors"
	"testing"
)

func TestSetTSAURLClearsNativeErrorState(t *testing.T) {
	var clearCalls int
	ctx := &fakeNativeContext{
		clearErrorFunc: func() {
			clearCalls++
		},
	}

	cli := &Client{ctx: ctx, config: defaultConfig()}
	if err := cli.SetTSAURL("http://tsa.example"); err != nil {
		t.Fatalf("SetTSAURL failed: %v", err)
	}
	if clearCalls != 1 {
		t.Fatalf("ClearError calls = %d, want 1", clearCalls)
	}
}

func TestSetTSAURLReportsNativeFailure(t *testing.T) {
	ctx := &fakeNativeContext{
		setTSAURLFunc: func(url string) uint64 {
			if url != "http://tsa.example" {
				t.Fatalf("TSA URL = %q, want configured URL", url)
			}

			return uint64(ErrorLibraryNotInitialized)
		},
	}

	cli := &Client{ctx: ctx, config: defaultConfig()}
	err := cli.SetTSAURL("http://tsa.example")
	if err == nil {
		t.Fatal("SetTSAURL unexpectedly succeeded")
	}
	var nativeErr *KalkanError
	if !errors.As(err, &nativeErr) || nativeErr.Code != ErrorLibraryNotInitialized {
		t.Fatalf("SetTSAURL error = %v, want ErrorLibraryNotInitialized", err)
	}
}
