package kalkan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

const maxSignerID = int(^uint32(0) >> 1)

// Client owns one initialized KalkanCrypt backend session.
//
// KalkanCrypt stores process-global state inside the native library. The
// low-level ckalkan package therefore allows one active native client per
// process and serializes native calls. Java clients own independent subprocesses.
// Individual calls are serialized; a LoadKeyStore call followed by signing is
// not atomic. Callers using different key stores must synchronize the complete
// load-and-sign sequence or use separate processes.
// A Client is safe for concurrent method calls, subject to the callback contract
// of [Observer]. It must be created with [Open]; its zero value is not initialized.
type Client struct {
	mu       sync.Mutex
	pemCache atomic.Pointer[pemCacheEntry]
	gate     chan struct{}
	closing  *closeState
	session  backend
	config   runtimeConfig
	logger   *slog.Logger
}

type closeState struct {
	done chan struct{}
	err  error
}

// Open loads and initializes KalkanCrypt.
//
// The context is checked before and between Go setup steps and while waiting
// for the Client call gate. For the native backend it cannot interrupt the
// low-level process mutex, library loading, or an active SDK call. For Java it
// cancels worker startup and protocol requests by terminating the subprocess.
// Cleanup after failed or canceled setup waits without a context.
func Open(ctx context.Context, options ...Option) (*Client, error) {
	return openWithBackendFactory(ctx, options, openBackend)
}

// Close releases the backend session. It may be called more than once. Close
// waits for an in-flight operation to return before releasing the backend.
// Repeated calls return the saved result of closing.
func (c *Client) Close() error {
	return c.CloseContext(context.Background())
}

// CloseContext releases the backend session with context-aware
// waiting. It may be called more than once.
//
// The context can stop waiting for a close queued behind an operation or
// already running in another goroutine. It does not cancel the active operation;
// that operation keeps the cancellation behavior of its own context and backend.
// CloseContext always starts closing, even when ctx is already canceled, and
// rejects new operations. Once closing has completed, repeated calls return its
// saved result, including when ctx is canceled.
func (c *Client) CloseContext(ctx context.Context) error {
	if c == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()

	if c.closing != nil {
		closing := c.closing
		c.mu.Unlock()

		return waitCloseContext(ctx, closing)
	}

	session := c.session
	if session == nil {
		c.pemCache.Store(nil)
		c.mu.Unlock()

		return nil
	}

	closing := &closeState{done: make(chan struct{})}
	c.closing = closing
	gate := c.callGateLocked()
	c.mu.Unlock()

	var start time.Time

	logCtx := context.Background()

	if c.logger != nil || c.config.observer != nil {
		start = time.Now()
		logCtx = context.WithoutCancel(ctx)
	}

	go c.closeBackend(logCtx, session, gate, closing, start)

	return waitCloseContext(ctx, closing)
}

func (c *Client) closeBackend(ctx context.Context, session backend, gate chan struct{}, closing *closeState, start time.Time) {
	<-gate

	var (
		nativeStart               time.Time
		queueWait, nativeDuration time.Duration
	)

	if !start.IsZero() {
		nativeStart = time.Now()
		queueWait = nativeStart.Sub(start)
	}

	var err error

	func() {
		defer releaseCallGate(gate)

		err = session.Close()

		if !start.IsZero() {
			nativeDuration = time.Since(nativeStart)
		}

		c.mu.Lock()
		c.session = nil
		c.pemCache.Store(nil)

		closing.err = err
		c.mu.Unlock()
	}()

	c.mu.Lock()
	close(closing.done)
	c.mu.Unlock()

	if !start.IsZero() {
		reportOperation(c, ctx, "Close", start, queueWait, nativeDuration, err)
	}
}

func waitCloseContext(ctx context.Context, closing *closeState) error {
	select {
	case <-closing.done:
		return closing.err
	default:
	}

	select {
	case <-closing.done:
		return closing.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// acquireBackend returns the open session with the client call gate held.
// The caller must release the returned gate.
func (c *Client) acquireBackend(ctx context.Context) (backend, chan struct{}, error) {
	if c == nil {
		return nil, nil, ErrClosed
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	c.mu.Lock()
	if c.session == nil || c.closing != nil {
		c.mu.Unlock()

		return nil, nil, ErrClosed
	}

	gate := c.callGateLocked()
	c.mu.Unlock()

	if done := ctx.Done(); done == nil {
		<-gate
	} else {
		select {
		case <-gate:
		case <-done:
			return nil, nil, ctx.Err()
		}

		if err := ctx.Err(); err != nil {
			releaseCallGate(gate)

			return nil, nil, err
		}
	}

	c.mu.Lock()
	session := c.session

	if session == nil || c.closing != nil {
		c.mu.Unlock()

		releaseCallGate(gate)

		return nil, nil, ErrClosed
	}
	c.mu.Unlock()

	return session, gate, nil
}

func releaseCallGate(gate chan struct{}) {
	gate <- struct{}{}
}

func (c *Client) callGateLocked() chan struct{} {
	if c.gate == nil {
		c.gate = make(chan struct{}, 1)
		c.gate <- struct{}{}
	}

	return c.gate
}

func openWithBackendFactory(ctx context.Context, options []Option, factory backendFactory) (_ *Client, err error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cfg := defaultOpenConfig()

	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	session, err := factory(cfg)
	if err != nil {
		return nil, err
	}

	client := &Client{session: session, config: cfg.runtime(), logger: cfg.runtimeLogger()}
	keepOpen := false

	defer func() {
		if !keepOpen {
			if closeErr := client.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}
	}()

	if err := setupOpenedClient(ctx, client, cfg); err != nil {
		return nil, err
	}

	for _, cert := range cfg.trusted {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if err := client.LoadTrustedCertificate(ctx, cert); err != nil {
			return nil, err
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	keepOpen = true

	return client, nil
}

func setupOpenedClient(ctx context.Context, client *Client, cfg config) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := withOperations(client, ctx, "Init", func(operations sessionInitializer) error {
		return operations.Init()
	}); err != nil {
		return fmt.Errorf("kalkan: initialize backend: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := withOperations(client, ctx, "SetTSAURL", func(operations networkSettings) error {
		return operations.SetTSAURL(cfg.tsaURL)
	}); err != nil {
		return fmt.Errorf("kalkan: configure TSA URL: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if cfg.proxy != nil {
		if err := withOperations(client, ctx, "SetProxy", func(operations networkSettings) error {
			return operations.SetProxy(cfg.proxy.native())
		}); err != nil {
			return fmt.Errorf("kalkan: configure proxy: %w", err)
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return nil
}

// withOperations runs a supported operation under the client call gate.
// Observations are reported after releasing the gate.
func withOperations[T any](c *Client, ctx context.Context, operation string, call func(T) error) error {
	_, err := withOperationsResult(c, ctx, operation, func(operations T) (struct{}, error) {
		return struct{}{}, call(operations)
	})

	return err
}

// withOperationsResult returns a supported operation's result.
// expectedCodes mark accepted native statuses in diagnostics.
func withOperationsResult[T, N any](c *Client, ctx context.Context, operation string, call func(N) (T, error), expectedCodes ...ckalkan.ErrorCode) (T, error) {
	return withBackendResult(c, ctx, operation, func(session backend) (T, error) {
		capability, ok := session.WithContext(ctx).(N)
		if !ok {
			var zero T
			return zero, unsupportedOperation(operation)
		}

		return call(capability)
	}, expectedCodes...)
}

// withBackend runs a session operation under the client call gate.
func withBackend(c *Client, ctx context.Context, operation string, call func(backend) error) error {
	_, err := withBackendResult(c, ctx, operation, func(session backend) (struct{}, error) {
		return struct{}{}, call(session)
	})

	return err
}

func withBackendResult[T any](c *Client, ctx context.Context, operation string, call func(backend) (T, error), expectedCodes ...ckalkan.ErrorCode) (T, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	diagnostics := c != nil && (c.logger != nil || c.config.observer != nil)

	var start time.Time
	if diagnostics {
		start = time.Now()
	}

	session, gate, err := c.acquireBackend(ctx)

	var queueWait, nativeDuration time.Duration
	if diagnostics {
		queueWait = time.Since(start)
	}

	var result T

	if err == nil {
		func() {
			defer releaseCallGate(gate)

			var nativeStart time.Time
			if diagnostics {
				nativeStart = time.Now()
			}

			result, err = call(session)
			err = session.NormalizeError(err)

			if diagnostics {
				nativeDuration = time.Since(nativeStart)
			}
		}()
	}

	if diagnostics {
		reportOperation(c, ctx, operation, start, queueWait, nativeDuration, err, expectedCodes...)
	}

	return result, err
}

func unsupportedOperation(operation string) error {
	return fmt.Errorf("kalkan: backend does not support %s", operation)
}

func validateSignerID(field string, value int) error {
	if value < 0 {
		return fmt.Errorf("%w: %s must be non-negative", ErrInvalidInput, field)
	}

	if value > maxSignerID {
		return fmt.Errorf("%w: %s must be in range 0..%d", ErrInvalidInput, field, maxSignerID)
	}

	return nil
}
