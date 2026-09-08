package kalkan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestObserverReportsSafeOutcomesWithoutChangingErrors(t *testing.T) {
	const secret = "https://user:password@private.example/path?token=secret"
	for _, test := range []struct {
		name         string
		err          error
		expectedCode ckalkan.ErrorCode
		wantClass    string
		wantCode     ckalkan.ErrorCode
	}{
		{name: "success", wantClass: "none"},
		{name: "native", err: &ckalkan.KalkanError{Code: ckalkan.ErrorVerifySign, Message: secret}, wantClass: "native_failure", wantCode: ckalkan.ErrorVerifySign},
		{name: "plain", err: errors.New(secret), wantClass: "operation_failure"},
		{name: "output limit", err: &ckalkan.OutputBufferLimitError{Operation: secret, Requested: 2, Limit: 1}, wantClass: "output_limit", wantCode: ckalkan.ErrorBufferTooSmall},
		{name: "expected", err: &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound, Message: secret}, expectedCode: ckalkan.ErrorCertNotFound, wantClass: "expected_status", wantCode: ckalkan.ErrorCertNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs bytes.Buffer
				var observation OperationObservation
				var count int
				client := &Client{session: newNativeBackend(&fakeSDK{}), logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), config: runtimeConfig{observer: func(_ context.Context, event OperationObservation) { observation = event; count++ }}}
				result, err := withOperationsResult(client, context.Background(), "TestOperation", func(sessionInitializer) (int, error) {
					time.Sleep(time.Millisecond)
					return 7, test.err
				}, test.expectedCode)
				if result != 7 || !errors.Is(err, test.err) {
					t.Fatalf("public result/error changed: result=%d, same error=%t", result, errors.Is(err, test.err))
				}
				if count != 1 || observation.Operation != "TestOperation" || observation.ErrorClass != test.wantClass || observation.NativeCode != test.wantCode || observation.Expected != (test.expectedCode != 0) {
					t.Fatalf("observation = %+v, count = %d", observation, count)
				}
				if observation.NativeDuration != time.Millisecond || observation.QueueWait != 0 || observation.TotalDuration != time.Millisecond {
					t.Fatalf("invalid timings: %+v", observation)
				}
				if strings.Contains(logs.String(), secret) || strings.Contains(fmt.Sprint(observation), secret) || strings.Contains(logs.String(), `"error":`) {
					t.Fatal("diagnostics exposed sensitive error data")
				}
				if !strings.Contains(logs.String(), `"error_class":"`+test.wantClass+`"`) {
					t.Fatalf("missing error class: %s", logs.String())
				}
				if test.wantCode != 0 && !strings.Contains(logs.String(), test.wantCode.Hex()) {
					t.Fatalf("missing native code: %s", logs.String())
				}
				if test.expectedCode != 0 && !strings.Contains(logs.String(), `"level":"DEBUG"`) {
					t.Fatalf("expected status logged above Debug: %s", logs.String())
				}
			})
		})
	}
}

func TestObserverMeasuresCanceledQueueWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		events := make(chan OperationObservation, 1)
		client := &Client{session: newNativeBackend(&fakeSDK{}), config: runtimeConfig{observer: func(_ context.Context, event OperationObservation) { events <- event }}}
		_, gate, err := client.acquireBackend(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer releaseCallGate(gate)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		queued := &observedQueueContext{Context: ctx, waiting: make(chan struct{})}
		result := make(chan error, 1)
		go func() {
			result <- withOperations(client, queued, "Queued", func(sessionInitializer) error {
				t.Error("canceled waiter entered native call")
				return nil
			})
		}()
		awaitTestEvent(t, queued.waiting, "native gate wait")
		const queueDelay = 5 * time.Millisecond
		time.Sleep(queueDelay)
		cancel()
		if err := awaitTestEvent(t, result, "canceled queue result"); !errors.Is(err, context.Canceled) {
			t.Fatalf("queue error = %v", err)
		}
		event := awaitTestEvent(t, events, "queue observation")
		if event.QueueWait != queueDelay || event.NativeDuration != 0 || event.TotalDuration != queueDelay || event.ErrorClass != "canceled" {
			t.Fatalf("queue observation = %+v", event)
		}
	})
}

func TestObserverSeparatesQueueNativeAndCallbackTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var observation OperationObservation
		client := &Client{
			session: newNativeBackend(&fakeSDK{hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
				time.Sleep(3 * time.Millisecond)
				return []byte("digest"), nil
			}}),
			config: runtimeConfig{observer: func(_ context.Context, event OperationObservation) {
				time.Sleep(7 * time.Millisecond)
				observation = event
			}},
		}
		_, gate, err := client.acquireBackend(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		unblock := sync.OnceFunc(func() { releaseCallGate(gate) })
		defer unblock()
		queued := &observedQueueContext{Context: context.Background(), waiting: make(chan struct{})}
		type hashResult struct {
			digest *Digest
			err    error
		}
		result := make(chan hashResult, 1)
		start := time.Now()
		go func() {
			digest, err := client.Hash(queued, HashRequest{Data: Bytes([]byte("data"))})
			result <- hashResult{digest: digest, err: err}
		}()
		awaitTestEvent(t, queued.waiting, "queued Hash")
		time.Sleep(5 * time.Millisecond)
		unblock()

		got := awaitTestEvent(t, result, "observed Hash result")
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.digest == nil || string(got.digest.Data) != "digest" || got.digest.Algorithm != SHA256 {
			t.Fatalf("Hash result = %+v", got.digest)
		}
		if observation.Operation != "Hash" || observation.ErrorClass != "none" {
			t.Fatalf("Hash observation = %+v", observation)
		}
		if observation.QueueWait != 5*time.Millisecond || observation.NativeDuration != 3*time.Millisecond || observation.TotalDuration != 8*time.Millisecond {
			t.Fatalf("timings must separate queue/native work and exclude the observer: %+v", observation)
		}
		if elapsed := time.Since(start); elapsed != 15*time.Millisecond {
			t.Fatalf("Hash including observer took %v, want 15ms", elapsed)
		}
	})
}

// Signal when lockLibrary consults Done, so cancellation cannot happen before
// the helper starts measuring the queued attempt.
type observedQueueContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *observedQueueContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestObserverDoesNotHoldNativeGate(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	secondNative := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var observed atomic.Int32
	var calls atomic.Int32
	client := &Client{session: newNativeBackend(&fakeSDK{initFunc: func() error {
		if calls.Add(1) == 2 {
			close(secondNative)
		}
		return nil
	}}), config: runtimeConfig{observer: func(context.Context, OperationObservation) {
		if observed.Add(1) == 1 {
			close(entered)
			<-release
		}
	}}}
	call := func() error {
		return withOperations(client, context.Background(), "Init", func(native sessionInitializer) error { return native.Init() })
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- call() }()
	awaitTestEvent(t, entered, "blocked observer")
	secondDone := make(chan error, 1)
	go func() { secondDone <- call() }()
	awaitTestEvent(t, secondNative, "native call while observer blocks")
	if err := awaitTestEvent(t, secondDone, "second call result"); err != nil {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := awaitTestEvent(t, firstDone, "first call result"); err != nil {
		t.Fatal(err)
	}
}

func TestCloseObserverRunsAfterSavedResultAndGateRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nativeErr := errors.New("private close details")
		entered := make(chan OperationObservation, 1)
		release := make(chan struct{})
		exited := make(chan struct{})
		var releaseOnce sync.Once
		defer releaseOnce.Do(func() { close(release) })
		client := &Client{session: newNativeBackend(&fakeSDK{closeFunc: func() error { time.Sleep(time.Millisecond); return nativeErr }}), config: runtimeConfig{observer: func(_ context.Context, event OperationObservation) { entered <- event; <-release; close(exited) }}}
		closed := make(chan error, 1)
		go func() { closed <- client.Close() }()
		event := awaitTestEvent(t, entered, "Close observer")
		if event.Operation != "Close" || event.ErrorClass != "operation_failure" || event.NativeDuration != time.Millisecond || event.QueueWait != 0 || event.TotalDuration != time.Millisecond {
			t.Fatalf("Close observation = %+v", event)
		}
		if err := awaitTestEvent(t, closed, "Close result before observer returns"); !errors.Is(err, nativeErr) {
			t.Fatalf("Close returned a different error: %v", err)
		}
		select {
		case <-client.gate:
			releaseCallGate(client.gate)
		default:
			t.Fatal("Close observer holds native gate")
		}
		if err := client.Close(); !errors.Is(err, nativeErr) {
			t.Fatalf("repeated Close lost error: %v", err)
		}
		releaseOnce.Do(func() { close(release) })
		awaitTestEvent(t, exited, "Close observer completion")
	})
}

func TestWithObserverCoversOpenSetupAndClose(t *testing.T) {
	events := make(chan OperationObservation, 4)
	client, err := openWithBackendFactory(context.Background(), []Option{WithLibraryPath(testLibraryPath()), WithObserver(func(_ context.Context, event OperationObservation) { events <- event })}, func(config) (backend, error) { return newNativeBackend(&fakeSDK{}), nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Init", "SetTSAURL"} {
		if event := awaitTestEvent(t, events, name); event.Operation != name {
			t.Fatalf("operation = %q, want %q", event.Operation, name)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if event := awaitTestEvent(t, events, "Close"); event.Operation != "Close" {
		t.Fatalf("operation = %q, want Close", event.Operation)
	}
}
