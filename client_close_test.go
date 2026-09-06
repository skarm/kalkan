package kalkan

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCloseContextStartsWithCanceledContext(t *testing.T) {
	var calls atomic.Int32
	client := &Client{library: &fakeNative{closeFunc: func() error {
		calls.Add(1)
		return nil
	}}}
	_, gate, err := client.lockLibrary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release := sync.OnceFunc(func() { releaseLibraryGate(gate) })
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.CloseContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("CloseContext = %v, want canceled while gate is held", err)
	}
	if _, _, err := client.lockLibrary(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("new operation = %v, want ErrClosed", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("native Close calls before release = %d", got)
	}
	release()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseContext(ctx); err != nil {
		t.Fatalf("completed CloseContext = %v, want saved success", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("native Close calls = %d, want 1", got)
	}
}

func TestCloseContextRetainsFailureAfterCanceledWait(t *testing.T) {
	want := errors.New("native close failed")
	entered := make(chan struct{})
	proceed := make(chan struct{})
	release := sync.OnceFunc(func() { close(proceed) })
	t.Cleanup(release)
	client := &Client{library: &fakeNative{closeFunc: func() error {
		close(entered)
		<-proceed
		return want
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() { result <- client.CloseContext(ctx) }()
	awaitTestEvent(t, entered, "native Close")
	cancel()
	if err := awaitTestEvent(t, result, "canceled wait"); !errors.Is(err, context.Canceled) {
		t.Fatalf("CloseContext = %v, want canceled", err)
	}
	release()
	if err := client.Close(); !errors.Is(err, want) {
		t.Fatalf("Close = %v, want native failure", err)
	}
	if err := client.CloseContext(ctx); !errors.Is(err, want) {
		t.Fatalf("completed CloseContext = %v, want saved failure", err)
	}
}
