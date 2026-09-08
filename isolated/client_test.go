package isolated

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/ckalkan"
)

// The helper is a real child process, including inherited-handle redirection.
// Its fake SDK lets tests force hangs and crashes without a native installation.
func TestIsolatedWorkerHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "isolated-worker-test" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if strings.HasPrefix(mode, "broken-") {
		runBrokenWorker(mode)
		os.Exit(0)
	}
	transport, err := preserveProtocolStreams()
	if err != nil {
		os.Exit(1)
	}
	err = serve(context.Background(), transport, func(_ context.Context, _ libraryConfig, observer kalkan.Observer) (workerSession, error) {
		if mode == "startup-hang" {
			select {}
		}
		if mode == "no-observer" && observer != nil {
			return nil, errors.New("worker enabled unrequested observations")
		}
		if observer == nil {
			observer = func(context.Context, kalkan.OperationObservation) {}
		}
		if mode == "startup-error" {
			observer(context.Background(), kalkan.OperationObservation{Operation: "Init", ErrorClass: "unavailable"})
			return nil, fmt.Errorf("startup diagnostic secret: %w", kalkan.ErrUnavailable)
		}
		fmt.Fprintln(os.Stdout, "native stdout must not enter the protocol")
		fmt.Fprintln(os.Stderr, "native stderr must not enter the protocol")
		observer(context.Background(), kalkan.OperationObservation{Operation: "Init", ErrorClass: "none"})
		return &helperSession{mode: mode, observer: observer}, nil
	})
	_ = transport.Close()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

type helperSession struct {
	sdkClient
	mode     string
	observer kalkan.Observer
}

func (s *helperSession) Hash(_ context.Context, req kalkan.HashRequest) (*kalkan.Digest, error) {
	if s.mode == "echo" {
		return &kalkan.Digest{Algorithm: req.Algorithm, Data: req.Data.Describe().Data}, nil
	}
	data := string(req.Data.Describe().Data)
	if data == "crash" {
		os.Exit(23)
	}
	defer s.observer(context.Background(), kalkan.OperationObservation{Operation: "HashData", ErrorClass: "none"})
	switch {
	case data == "native-error":
		return nil, &ckalkan.OutputBufferLimitError{Operation: "HashData", Requested: 20, Limit: 10}
	case strings.HasPrefix(data, "wait:"):
		if err := waitForRelease(strings.TrimPrefix(data, "wait:")); err != nil {
			return nil, err
		}
	}
	return &kalkan.Digest{Algorithm: req.Algorithm, Data: []byte(strconv.Itoa(os.Getpid()))}, nil
}

func (s *helperSession) Close() error {
	if s.mode == "close-hang" {
		select {}
	}
	if strings.HasPrefix(s.mode, "close-wait:") {
		if err := waitForRelease(strings.TrimPrefix(s.mode, "close-wait:")); err != nil {
			return err
		}
	}
	if s.mode == "close-error" {
		s.observer(context.Background(), kalkan.OperationObservation{Operation: "Close", ErrorClass: "native_failure", NativeCode: ckalkan.ErrorMemory})
		return &ckalkan.KalkanError{Code: ckalkan.ErrorMemory}
	}
	s.observer(context.Background(), kalkan.OperationObservation{Operation: "Close", ErrorClass: "none"})
	return nil
}

func waitForRelease(path string) error {
	if err := os.WriteFile(path+".entered", []byte("entered"), 0o600); err != nil {
		return err
	}
	for {
		if _, err := os.Stat(path + ".release"); err == nil {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func runBrokenWorker(mode string) {
	for {
		request, err := readMessage(os.Stdin)
		if err != nil {
			return
		}
		response := message{ID: request.ID, Operation: request.Operation, Payload: nullPayload()}
		if request.Operation == opClose && mode == "broken-close-result" {
			response.Payload = wirePayload{metadata: []byte{1}}
		}
		if request.Operation == "Hash" {
			switch mode {
			case "broken-id":
				response.ID++
			case "broken-result":
				response.Payload = wirePayload{metadata: []byte{255}}
			case "broken-header":
				var header [8]byte
				binary.BigEndian.PutUint64(header[:], 3)
				_, _ = os.Stdout.Write(header[:])
				return
			case "broken-truncated":
				_, _ = os.Stdout.Write([]byte{0, 0, 0, 0, 0, 0, 0, 20, 0})
				return
			}
		}
		if writeMessage(os.Stdout, response) != nil {
			return
		}
		if mode == "broken-unread" && request.Operation == "Open" {
			// Leave the parent blocked in a pipe write until cancellation kills us.
			time.Sleep(time.Hour)
			return
		}
		if request.Operation == "Close" {
			if mode == "broken-close-result" {
				time.Sleep(time.Hour)
			}
			return
		}
	}
}

func helperConfig(t *testing.T) Config {
	t.Helper()
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Config{WorkerPath: worker, LibraryPath: filepath.Join(t.TempDir(), "fake-library")}
}

func openHelper(t *testing.T, mode string, change func(*Config)) *Client {
	t.Helper()
	cfg := helperConfig(t)
	if change != nil {
		change(&cfg)
	}
	cfg.WorkerArgs = []string{"-test.run=^TestIsolatedWorkerHelper$", "isolated-worker-test", mode}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = client.CloseContext(ctx)
		awaitExit(t, client)
	})
	return client
}

func awaitExit(t *testing.T, client *Client) {
	t.Helper()
	select {
	case <-client.exited:
	case <-time.After(3 * time.Second):
		t.Error("worker was not reaped")
	}
}

func hash(ctx context.Context, client *Client, value string) (*kalkan.Digest, error) {
	return client.Hash(ctx, kalkan.HashRequest{Data: kalkan.Bytes([]byte(value))})
}

func waitEntered(t *testing.T, path string) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path + ".entered"); err == nil {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("worker did not enter the operation")
		case <-ticker.C:
		}
	}
}

func TestIsolatedWorkersHaveIndependentProcesses(t *testing.T) {
	first, second := openHelper(t, "normal", nil), openHelper(t, "normal", nil)
	one, err := hash(context.Background(), first, "pid")
	if err != nil {
		t.Fatal(err)
	}
	two, err := hash(context.Background(), second, "pid")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(one.Data, two.Data) {
		t.Fatal("clients share the same process")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := first.CloseContext(canceled); err != nil {
		t.Fatalf("completed close with canceled context = %v", err)
	}
	if _, err := hash(context.Background(), second, "still alive"); err != nil {
		t.Fatal(err)
	}
	if _, err := hash(context.Background(), first, "closed"); !errors.Is(err, kalkan.ErrClosed) {
		t.Fatalf("closed error = %v", err)
	}
}

func TestRequestAndResponseLargerThan128MiB(t *testing.T) {
	data := bytes.Repeat([]byte{0, 128, 255, 17}, (129<<20)/4)
	client := openHelper(t, "echo", nil)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	result, err := client.Hash(ctx, kalkan.HashRequest{Algorithm: kalkan.GOST2015_512, Data: kalkan.Bytes(data)})
	if err != nil || result == nil || result.Algorithm != kalkan.GOST2015_512 || !bytes.Equal(result.Data, data) {
		t.Fatalf("binary round trip failed: %v", err)
	}
}

func TestInputLimitRejectsBeforeWorkerReceivesData(t *testing.T) {
	// This fake deliberately does not enforce SDK limits. An oversized input
	// must be rejected by the parent, while a smaller call must still succeed.
	client := openHelper(t, "echo", func(cfg *Config) { cfg.MaxInputSize = 16 })
	if _, err := client.Hash(context.Background(), kalkan.HashRequest{Data: kalkan.Bytes(make([]byte, 1024))}); !errors.Is(err, kalkan.ErrInvalidInput) {
		t.Fatalf("oversized input = %v", err)
	}
	result, err := client.Hash(context.Background(), kalkan.HashRequest{Data: kalkan.Bytes([]byte("small"))})
	if err != nil || result == nil || string(result.Data) != "small" {
		t.Fatalf("call after locally rejected input = %v, %v", result, err)
	}
}

type observedWriter struct {
	io.ReadWriteCloser
	size    int
	entered chan struct{}
}

func (w *observedWriter) Write(data []byte) (int, error) {
	if len(data) == w.size {
		close(w.entered)
	}
	return w.ReadWriteCloser.Write(data)
}

func TestCancellationDuringWriteReturnsOwnershipOfInput(t *testing.T) {
	client := openHelper(t, "broken-unread", nil)
	data := make([]byte, 8<<20)
	writing := make(chan struct{})
	client.mu.Lock()
	client.conn = &observedWriter{ReadWriteCloser: client.conn, size: len(data), entered: writing}
	client.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.Hash(ctx, kalkan.HashRequest{Data: kalkan.Bytes(data)})
		done <- err
	}()
	select {
	case <-writing:
	case <-time.After(3 * time.Second):
		t.Fatal("sender did not enter the raw block write")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled send = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sender remained blocked after cancellation")
	}
	// Reuse the caller's buffer immediately. The race detector must see no
	// concurrent transport access after the API has returned.
	for i := range data {
		data[i] = 0xff
	}
	awaitExit(t, client)
}

func TestCancellationWhileQueuedPreservesWorker(t *testing.T) {
	client := openHelper(t, "normal", nil)
	path := filepath.Join(t.TempDir(), "wait")
	active := make(chan error, 1)
	go func() { _, err := hash(context.Background(), client, "wait:"+path); active <- err }()
	waitEntered(t, path)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := hash(ctx, client, "queued"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued error = %v", err)
	}
	if err := os.WriteFile(path+".release", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-active; err != nil {
		t.Fatal(err)
	}
	if _, err := hash(context.Background(), client, "alive"); err != nil {
		t.Fatal(err)
	}
}

func TestQueuedCallHasNoInternalTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// A held gate keeps this call waiting without starting a process.
		client := &Client{gate: make(chan struct{}, 1), exited: make(chan struct{})}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := hash(ctx, client, "queued"); done <- err }()
		time.Sleep(time.Hour)
		select {
		case err := <-done:
			t.Fatalf("call ended before caller cancellation: %v", err)
		default:
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled queued call = %v", err)
		}
	})
}

func TestCancellationOfActiveCallKillsOnlyItsWorker(t *testing.T) {
	client, other := openHelper(t, "normal", nil), openHelper(t, "normal", nil)
	path := filepath.Join(t.TempDir(), "wait")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	active := make(chan error, 1)
	go func() { _, err := hash(ctx, client, "wait:"+path); active <- err }()
	waitEntered(t, path)
	if _, err := hash(context.Background(), other, "parallel"); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-active; !errors.Is(err, context.Canceled) {
		t.Fatalf("active error = %v", err)
	}
	awaitExit(t, client)
	if _, err := hash(context.Background(), client, "failed"); !errors.Is(err, ErrWorkerFailed) {
		t.Fatalf("subsequent error = %v", err)
	}
}

func TestWorkerCrashAndMalformedResponsesAreTerminal(t *testing.T) {
	for _, mode := range []string{"normal", "broken-id", "broken-result", "broken-header", "broken-truncated"} {
		t.Run(mode, func(t *testing.T) {
			client := openHelper(t, mode, nil)
			_, err := hash(context.Background(), client, "crash")
			if !errors.Is(err, ErrWorkerFailed) {
				t.Fatalf("failure = %v", err)
			}
			if mode != "normal" && !errors.Is(err, ErrProtocol) {
				t.Fatalf("protocol failure = %v", err)
			}
			awaitExit(t, client)
			if _, err := hash(context.Background(), client, "next"); !errors.Is(err, ErrWorkerFailed) {
				t.Fatalf("subsequent failure = %v", err)
			}
		})
	}
}

func TestNativeErrorLeavesSessionUsable(t *testing.T) {
	client := openHelper(t, "normal", nil)
	_, err := hash(context.Background(), client, "native-error")
	var limit *ckalkan.OutputBufferLimitError
	if !errors.As(err, &limit) || limit.Requested != 20 || limit.Limit != 10 {
		t.Fatalf("native limit = %v", err)
	}
	if _, err := hash(context.Background(), client, "small"); err != nil {
		t.Fatalf("session after recoverable error: %v", err)
	}
}

func TestCanceledCloseContextKillsWorkerAndSavesResult(t *testing.T) {
	client := openHelper(t, "close-hang", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.CloseContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled close = %v", err)
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			if err := client.Close(); !errors.Is(err, context.Canceled) {
				t.Errorf("close = %v", err)
			}
		})
	}
	wg.Wait()
	awaitExit(t, client)
	if err := client.Close(); !errors.Is(err, context.Canceled) {
		t.Fatalf("saved close = %v", err)
	}
}

func TestMalformedCloseAcknowledgementWaitsForWorkerExit(t *testing.T) {
	client := openHelper(t, "broken-close-result", nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := client.CloseContext(ctx); !errors.Is(err, ErrProtocol) || !errors.Is(err, ErrWorkerFailed) {
		t.Fatalf("malformed Close response = %v", err)
	}
	select {
	case <-client.exited:
	default:
		t.Fatal("Close returned before the worker was reaped")
	}
}

func TestCloseContextDeadlineKillsWorker(t *testing.T) {
	client := openHelper(t, "close-hang", nil)
	ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
	defer cancel()
	if err := client.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close deadline = %v", err)
	}
	awaitExit(t, client)
	if err := client.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("saved close = %v", err)
	}
}

func TestCloseContextCanCancelConcurrentClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "close")
	client := openHelper(t, "close-wait:"+path, nil)
	done := make(chan error, 1)
	go func() { done <- client.Close() }()
	waitEntered(t, path)
	if _, err := hash(t.Context(), client, "closing"); !errors.Is(err, kalkan.ErrClosed) {
		t.Fatalf("call during close = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := client.CloseContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel concurrent close = %v", err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("first close = %v", err)
	}
	awaitExit(t, client)
}

func TestCloseWaitForActiveCallIsBounded(t *testing.T) {
	client := openHelper(t, "normal", nil)
	path := filepath.Join(t.TempDir(), "wait")
	done := make(chan error, 1)
	go func() { _, err := hash(context.Background(), client, "wait:"+path); done <- err }()
	waitEntered(t, path)
	ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
	defer cancel()
	if err := client.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close active call = %v", err)
	}
	if err := <-done; !errors.Is(err, ErrWorkerFailed) {
		t.Fatalf("interrupted call = %v", err)
	}
	awaitExit(t, client)
}

func TestCallContextDeadlineKillsWorker(t *testing.T) {
	client := openHelper(t, "normal", nil)
	path := filepath.Join(t.TempDir(), "wait")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := hash(ctx, client, "wait:"+path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("call deadline = %v", err)
	}
	awaitExit(t, client)
	if err := client.Close(); !errors.Is(err, ErrWorkerFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close after call deadline = %v, want original worker failure", err)
	}
}

func TestCloseObservationsSurviveErrorsAndAllowReentry(t *testing.T) {
	for _, mode := range []string{"normal", "close-error"} {
		t.Run(mode, func(t *testing.T) {
			observed := make(chan error, 1)
			var client *Client
			client = openHelper(t, mode, func(cfg *Config) {
				cfg.Observer = func(_ context.Context, value kalkan.OperationObservation) {
					if value.Operation == "Close" {
						observed <- client.Close()
					}
				}
			})
			err := client.Close()
			if mode == "normal" && err != nil {
				t.Fatal(err)
			}
			if mode == "close-error" && !errors.Is(err, &ckalkan.KalkanError{Code: ckalkan.ErrorMemory}) {
				t.Fatalf("close error = %v", err)
			}
			select {
			case callbackErr := <-observed:
				if (callbackErr == nil) != (err == nil) {
					t.Fatalf("callback Close = %v, first Close = %v", callbackErr, err)
				}
			case <-time.After(time.Second):
				t.Fatal("Close observation missing or callback deadlocked")
			}
		})
	}
}

func TestStartupFailuresAndStartupContextLifetime(t *testing.T) {
	for _, mode := range []string{"startup-hang", "startup-error"} {
		t.Run(mode, func(t *testing.T) {
			cfg := helperConfig(t)
			timeout := 5 * time.Second
			if mode == "startup-hang" {
				timeout = 100 * time.Millisecond
			}
			cfg.WorkerArgs = []string{"-test.run=^TestIsolatedWorkerHelper$", "isolated-worker-test", mode}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			client, err := Open(ctx, cfg)
			if client != nil || err == nil {
				t.Fatalf("Open = %v, %v", client, err)
			}
			if mode == "startup-hang" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			if mode == "startup-error" && !errors.Is(err, kalkan.ErrUnavailable) {
				t.Fatal(err)
			}
		})
	}
	cfg := helperConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cfg.WorkerArgs = []string{"-test.run=^TestIsolatedWorkerHelper$", "isolated-worker-test", "normal"}
	client, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	cancel()
	if _, err := hash(context.Background(), client, "alive"); err != nil {
		t.Fatal(err)
	}
}

func TestStartupFailureReportsObservationsWithoutLoggingSecrets(t *testing.T) {
	var logs bytes.Buffer
	var observations []kalkan.OperationObservation
	cfg := helperConfig(t)
	cfg.Proxy = &kalkan.Proxy{Password: "startup request secret"}
	cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	cfg.Observer = func(_ context.Context, observation kalkan.OperationObservation) {
		observations = append(observations, observation)
	}
	cfg.WorkerArgs = []string{"-test.run=^TestIsolatedWorkerHelper$", "isolated-worker-test", "startup-error"}
	client, err := Open(context.Background(), cfg)
	if client != nil || !errors.Is(err, kalkan.ErrUnavailable) {
		t.Fatalf("Open = %v, %v; want original startup error", client, err)
	}
	if len(observations) != 1 || observations[0].Operation != "Init" || observations[0].ErrorClass != "unavailable" {
		t.Fatalf("startup observations = %+v; want failed Init", observations)
	}
	var record struct {
		Level      string `json:"level"`
		Operation  string `json:"operation"`
		ErrorClass string `json:"error_class"`
	}
	if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
		t.Fatalf("decode startup log: %v", err)
	}
	if record.Level != "ERROR" || record.Operation != "Open" || record.ErrorClass != "operation_failure" {
		t.Fatalf("startup log = %+v; want failed Open", record)
	}
	for _, secret := range []string{cfg.Proxy.Password, "startup diagnostic secret"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("startup log exposed request or native error text")
		}
	}
}

func TestParentPipeClosureStopsHungWorker(t *testing.T) {
	client := openHelper(t, "normal", nil)
	path := filepath.Join(t.TempDir(), "wait")
	done := make(chan error, 1)
	go func() { _, err := hash(context.Background(), client, "wait:"+path); done <- err }()
	waitEntered(t, path)
	transport, ok := client.conn.(*pipeTransport)
	if !ok {
		t.Fatalf("transport = %T", client.conn)
	}
	if err := transport.writer.Close(); err != nil {
		t.Fatal(err)
	}
	awaitExit(t, client)
	if err := <-done; !errors.Is(err, ErrWorkerFailed) {
		t.Fatalf("orphan call = %v", err)
	}
}

func TestObserverReentryAndSafeLogging(t *testing.T) {
	var logs bytes.Buffer
	var client *Client
	observed := 0
	client = openHelper(t, "normal", func(cfg *Config) {
		cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		cfg.Observer = func(_ context.Context, value kalkan.OperationObservation) {
			if value.Operation == "HashData" && observed == 0 {
				observed++
				if _, err := hash(context.Background(), client, "reentrant"); err != nil {
					t.Error(err)
				}
			}
		}
	})
	if _, err := hash(context.Background(), client, "secret payload 123"); err != nil {
		t.Fatal(err)
	}
	if observed != 1 {
		t.Fatalf("observer calls = %d", observed)
	}

	observed = 0
	_, err := hash(context.Background(), client, "native-error")
	var limit *ckalkan.OutputBufferLimitError
	if !errors.As(err, &limit) || limit.Requested != 20 || limit.Limit != 10 {
		t.Fatalf("Hash error = %v; want the worker's output-buffer limit error", err)
	}
	if observed != 1 {
		t.Fatalf("observer calls for failed Hash = %d; want 1", observed)
	}

	if strings.Contains(logs.String(), "secret payload") || strings.Contains(logs.String(), "native stdout") {
		t.Fatalf("unsafe logs: %s", logs.String())
	}
}

func TestWorkerSkipsUnrequestedObservations(t *testing.T) {
	for _, logger := range []bool{false, true} {
		t.Run(fmt.Sprintf("logger=%t", logger), func(t *testing.T) {
			client := openHelper(t, "no-observer", func(cfg *Config) {
				if logger {
					cfg.Logger = slog.New(slog.DiscardHandler)
				}
			})
			if _, err := hash(context.Background(), client, "without observations"); err != nil {
				t.Fatal(err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestZeroClientAndInvalidConfig(t *testing.T) {
	var client Client
	if _, err := hash(context.Background(), &client, "zero"); !errors.Is(err, kalkan.ErrClosed) {
		t.Fatalf("zero client = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Config{}); !errors.Is(err, kalkan.ErrInvalidInput) {
		t.Fatalf("invalid config = %v", err)
	}
	cfg := helperConfig(t)
	cfg.WorkerPath = filepath.Join(t.TempDir(), "does-not-exist")
	// Windows may fail executable-extension lookup before starting the process.
	if _, err := Open(context.Background(), cfg); !errors.Is(err, os.ErrNotExist) && !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("missing worker = %v", err)
	}
}
