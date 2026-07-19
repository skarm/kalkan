package kalkan

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

const loggingTestTimeout = 2 * time.Second

func TestWithLockedLibraryLoggingDoesNotHoldNativeGate(t *testing.T) {
	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	secondNativeCall := make(chan struct{})
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}()

	var handled atomic.Int32
	handler := &callbackSlogHandler{
		handle: func(context.Context, slog.Record) error {
			if handled.Add(1) == 1 {
				close(handlerEntered)
				<-releaseHandler
			}

			return nil
		},
	}

	var nativeCalls atomic.Int32
	client := &Client{
		library: &fakeNative{
			initFunc: func() error {
				if nativeCalls.Add(1) == 2 {
					close(secondNativeCall)
				}

				return nil
			},
		},
		logger: slog.New(handler),
	}

	call := func() error {
		return withLockedLibrary(client, context.Background(), "Init", func(native initializer) error {
			return native.Init()
		})
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- call() }()
	awaitLoggingTest(t, handlerEntered, "first logger invocation")

	secondDone := make(chan error, 1)
	go func() { secondDone <- call() }()
	awaitLoggingTest(t, secondNativeCall, "second native call while the first logger is blocked")
	if err := awaitLoggingTest(t, secondDone, "second helper result"); err != nil {
		t.Fatalf("second helper call returned error: %v", err)
	}

	releaseOnce.Do(func() { close(releaseHandler) })
	if err := awaitLoggingTest(t, firstDone, "first helper result"); err != nil {
		t.Fatalf("first helper call returned error: %v", err)
	}
}

func TestWithLockedLibraryResultLoggingDoesNotHoldNativeGate(t *testing.T) {
	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	secondNativeCall := make(chan struct{})
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}()

	var handled atomic.Int32
	handler := &callbackSlogHandler{
		handle: func(context.Context, slog.Record) error {
			if handled.Add(1) == 1 {
				close(handlerEntered)
				<-releaseHandler
			}

			return nil
		},
	}

	var nativeCalls atomic.Int32
	client := &Client{
		library: &fakeNative{
			hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
				call := nativeCalls.Add(1)
				if call == 2 {
					close(secondNativeCall)
				}

				return []byte{byte(call)}, nil
			},
		},
		logger: slog.New(handler),
	}

	call := func() ([]byte, error) {
		return withLockedLibraryResult(client, context.Background(), "Hash", func(native hashing) ([]byte, error) {
			return native.HashData(ckalkan.SHA256, 0, []byte("payload"))
		})
	}

	firstDone := make(chan bytesResult, 1)
	go func() {
		result, err := call()
		firstDone <- bytesResult{result: result, err: err}
	}()
	awaitLoggingTest(t, handlerEntered, "first result logger invocation")

	secondDone := make(chan bytesResult, 1)
	go func() {
		result, err := call()
		secondDone <- bytesResult{result: result, err: err}
	}()
	awaitLoggingTest(t, secondNativeCall, "second result-returning native call while the first logger is blocked")

	second := awaitLoggingTest(t, secondDone, "second result-returning helper result")
	if second.err != nil {
		t.Fatalf("second helper call returned error: %v", second.err)
	}
	if len(second.result) != 1 || second.result[0] != 2 {
		t.Fatalf("second helper result = %v, want [2]", second.result)
	}

	releaseOnce.Do(func() { close(releaseHandler) })
	first := awaitLoggingTest(t, firstDone, "first result-returning helper result")
	if first.err != nil {
		t.Fatalf("first helper call returned error: %v", first.err)
	}
	if len(first.result) != 1 || first.result[0] != 1 {
		t.Fatalf("first helper result = %v, want [1]", first.result)
	}
}

func TestReentrantLoggerCanCallClientMethod(t *testing.T) {
	var nativeCalls atomic.Int32
	client := &Client{
		library: &fakeNative{
			hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
				return []byte{byte(nativeCalls.Add(1))}, nil
			},
		},
	}

	reentrantDone := make(chan error, 1)
	var reentered atomic.Bool
	client.logger = slog.New(&callbackSlogHandler{
		handle: func(context.Context, slog.Record) error {
			if !reentered.CompareAndSwap(false, true) {
				return nil
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			_, err := client.Hash(ctx, HashRequest{Data: Bytes([]byte("reentrant"))})
			reentrantDone <- err

			return nil
		},
	})

	outerDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("outer"))})
		outerDone <- err
	}()

	if err := awaitLoggingTest(t, reentrantDone, "reentrant client call"); err != nil {
		t.Fatalf("reentrant Hash returned error: %v", err)
	}
	if err := awaitLoggingTest(t, outerDone, "outer client call"); err != nil {
		t.Fatalf("outer Hash returned error: %v", err)
	}
	if got := nativeCalls.Load(); got != 2 {
		t.Fatalf("native calls = %d, want 2", got)
	}
}

func TestNativeCallErrorIsLoggedAfterGateRelease(t *testing.T) {
	nativeErr := errors.New("native hash failed")
	handlerEntered := make(chan loggedNativeCall, 1)
	releaseHandler := make(chan struct{})
	secondNativeCall := make(chan struct{})
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}()

	var handled atomic.Int32
	handler := &callbackSlogHandler{
		handle: func(_ context.Context, record slog.Record) error {
			if handled.Add(1) != 1 {
				return nil
			}

			logged := loggedNativeCall{level: record.Level, message: record.Message}
			record.Attrs(func(attr slog.Attr) bool {
				switch attr.Key {
				case "operation":
					logged.operation = attr.Value.String()
				case "error":
					logged.err, _ = attr.Value.Any().(error)
				}

				return true
			})
			handlerEntered <- logged
			<-releaseHandler

			return nil
		},
	}

	var nativeCalls atomic.Int32
	client := &Client{
		library: &fakeNative{
			hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
				if nativeCalls.Add(1) == 1 {
					return nil, nativeErr
				}

				close(secondNativeCall)

				return []byte("digest"), nil
			},
		},
		logger: slog.New(handler),
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("first"))})
		firstDone <- err
	}()

	logged := awaitLoggingTest(t, handlerEntered, "native error log")
	if logged.level != slog.LevelError || logged.message != "kalkan native call failed" || logged.operation != "Hash" {
		t.Fatalf("logged native call = %+v", logged)
	}
	if !errors.Is(logged.err, nativeErr) {
		t.Fatalf("logged error = %v, want %v", logged.err, nativeErr)
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("second"))})
		secondDone <- err
	}()
	awaitLoggingTest(t, secondNativeCall, "native call after logged error")
	if err := awaitLoggingTest(t, secondDone, "operation after logged error"); err != nil {
		t.Fatalf("second Hash returned error: %v", err)
	}

	releaseOnce.Do(func() { close(releaseHandler) })
	if err := awaitLoggingTest(t, firstDone, "failed operation result"); !errors.Is(err, nativeErr) {
		t.Fatalf("first Hash error = %v, want %v", err, nativeErr)
	}
}

func TestNativeCallbackPanicReleasesGate(t *testing.T) {
	panicValue := errors.New("fake native panic")
	var nativeCalls atomic.Int32
	client := &Client{
		library: &fakeNative{
			initFunc: func() error {
				if nativeCalls.Add(1) == 1 {
					panic(panicValue)
				}

				return nil
			},
		},
	}

	var recovered any
	func() {
		defer func() { recovered = recover() }()

		_ = withLockedLibrary(client, context.Background(), "Init", func(native initializer) error {
			return native.Init()
		})
	}()
	recoveredErr, ok := recovered.(error)
	if !ok || !errors.Is(recoveredErr, panicValue) {
		t.Fatalf("recovered panic = %v, want %v", recovered, panicValue)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := withLockedLibrary(client, ctx, "Init", func(native initializer) error {
		return native.Init()
	}); err != nil {
		t.Fatalf("helper call after panic returned error: %v", err)
	}
	if got := nativeCalls.Load(); got != 2 {
		t.Fatalf("native calls = %d, want 2", got)
	}
}

func TestCloseContextCompletesBeforeSlowLogger(t *testing.T) {
	handlerEntered := make(chan struct{})
	handlerExited := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}()

	handler := &callbackSlogHandler{
		handle: func(_ context.Context, record slog.Record) error {
			var operation string
			record.Attrs(func(attr slog.Attr) bool {
				if attr.Key == "operation" {
					operation = attr.Value.String()
				}

				return true
			})
			if operation != "Close" {
				return nil
			}

			close(handlerEntered)
			<-releaseHandler
			close(handlerExited)

			return nil
		},
	}
	client := &Client{
		library: &fakeNative{},
		logger:  slog.New(handler),
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.CloseContext(context.Background()) }()
	awaitLoggingTest(t, handlerEntered, "Close logger invocation")

	if err := awaitLoggingTest(t, closeDone, "CloseContext lifecycle completion"); err != nil {
		t.Fatalf("CloseContext returned error: %v", err)
	}

	select {
	case <-client.gate:
		client.gate <- struct{}{}
	case <-time.After(loggingTestTimeout):
		t.Fatal("native gate remained held while Close logger was blocked")
	}

	client.mu.Lock()
	library := client.library
	closing := client.closing
	client.mu.Unlock()
	if library != nil || closing != nil {
		t.Fatalf("client lifecycle after CloseContext = library %v, closing %v; want fully closed", library, closing)
	}
	if err := client.CloseContext(context.Background()); err != nil {
		t.Fatalf("repeated CloseContext returned error: %v", err)
	}

	releaseOnce.Do(func() { close(releaseHandler) })
	awaitLoggingTest(t, handlerExited, "Close logger completion")
}

type bytesResult struct {
	result []byte
	err    error
}

type loggedNativeCall struct {
	level     slog.Level
	message   string
	operation string
	err       error
}

type callbackSlogHandler struct {
	handle func(context.Context, slog.Record) error
}

func (h *callbackSlogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *callbackSlogHandler) Handle(ctx context.Context, record slog.Record) error {
	return h.handle(ctx, record)
}

func (h *callbackSlogHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *callbackSlogHandler) WithGroup(string) slog.Handler {
	return h
}

func awaitLoggingTest[T any](t *testing.T, ch <-chan T, event string) T {
	t.Helper()

	timer := time.NewTimer(loggingTestTimeout)
	defer timer.Stop()

	select {
	case value := <-ch:
		return value
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", event)
		var zero T

		return zero
	}
}
