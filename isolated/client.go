package isolated

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"time"

	"github.com/skarm/kalkan"
)

// Client owns one worker process and its SDK session. Calls are serialized per
// client; independent clients run in parallel in separate processes. Each call
// uses only its caller's context, including the queue wait, with no internal
// timeout. A call canceled after transmission starts kills the worker and
// permanently fails the client. Cancellation while queued leaves the worker
// intact. No operation is retried. Callers must synchronize multi-call
// load-and-sign sequences.
// A Client is safe for concurrent use, subject to the observer requirements in
// [Config]. Its zero value is not ready for use; create clients with [Open].
type Client struct {
	mu           sync.Mutex
	gate         chan struct{}
	conn         io.ReadWriteCloser
	cmd          *exec.Cmd
	exited       chan struct{}
	waitErr      error
	terminal     error
	closing      *closeState
	nextID       uint64
	maxInputSize int64
	logger       *slog.Logger
	observer     kalkan.Observer
}

type closeState struct {
	done         chan struct{}
	cancel       context.CancelCauseFunc
	err          error
	observations []kalkan.OperationObservation
}

// exchangeResult retains the worker response alongside an operation error.
// A failed SDK operation can still return native-call observations.
type exchangeResult struct {
	message message
	err     error
}

func (c *Client) stateError() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closing != nil {
		return kalkan.ErrClosed
	}

	if c.terminal == nil {
		select {
		case <-c.exited:
			return &WorkerError{Cause: c.waitErr}
		default:
		}
	}

	return c.terminal
}

func (c *Client) stop(cause error) error {
	c.mu.Lock()
	if c.terminal == nil {
		c.terminal = &WorkerError{Cause: cause}
	}

	err, conn := c.terminal, c.conn
	c.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}

	_ = c.cmd.Process.Kill()

	return err
}

// waitProcess reaps the child exactly once and publishes its exit status.
// It waits for the call gate before closing pipes so a final response can drain.
func (c *Client) waitProcess() {
	err := c.cmd.Wait()
	c.mu.Lock()
	c.waitErr = err
	close(c.exited)
	c.mu.Unlock()
	// Let an in-flight reader consume a complete final response before closing
	// our pipes. The peer's exit itself terminates incomplete reads with EOF.
	<-c.gate
	c.mu.Lock()
	if c.terminal == nil && c.closing == nil {
		c.terminal = &WorkerError{Cause: err}
	}

	conn := c.conn
	c.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}

	c.gate <- struct{}{}
}

func (c *Client) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := c.stateError(); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.gate:
	}

	if err := ctx.Err(); err != nil {
		c.gate <- struct{}{}
		return err
	}

	if err := c.stateError(); err != nil {
		c.gate <- struct{}{}
		return err
	}

	return nil
}

// exchange sends one request and validates its matching response. The caller
// must hold the call gate. A response may contain observations alongside an
// operation error; transport failures return a zero message and stop the worker.
func (c *Client) exchange(ctx context.Context, operation string, payload wirePayload) (message, error) {
	c.nextID++
	request := message{ID: c.nextID, Operation: operation, Payload: payload}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	done := make(chan exchangeResult, 1)

	go func() {
		err := writeMessage(conn, request)

		var response message
		if err == nil {
			response, err = readMessage(conn)
		}

		done <- exchangeResult{response, err}
	}()

	var result exchangeResult
	select {
	case result = <-done:
	case <-ctx.Done():
		select {
		case result = <-done:
		default:
			_ = c.stop(ctx.Err())
			// The sender borrows caller bytes. Closing the pipes and killing the
			// child interrupts I/O; join the sender before returning ownership.
			<-done

			return message{}, ctx.Err()
		}
	}

	if result.err != nil {
		if errors.Is(result.err, errMetadataTooLarge) {
			// Header encoding failed before any request bytes were written.
			c.nextID--
			return message{}, result.err
		}

		return message{}, c.stop(result.err)
	}

	if result.message.ID != request.ID || result.message.Operation != operation {
		return message{}, c.failProtocol(errors.New("response does not match request"))
	}

	if err := result.message.Error; err != nil {
		if errors.Is(err, ErrProtocol) {
			return result.message, c.stop(err)
		}

		return result.message, err
	}

	return result.message, nil
}

func (c *Client) call(ctx context.Context, operation string, request any, decode func(wirePayload) error) error {
	if c == nil || c.gate == nil {
		return kalkan.ErrClosed
	}

	if ctx == nil {
		ctx = context.Background()
	}

	started := time.Now()

	if err := c.acquire(ctx); err != nil {
		return err
	}

	result := func() exchangeResult {
		defer func() { c.gate <- struct{}{} }()

		payload, err := encodeRequest(operation, request, c.maxInputSize)
		if err != nil {
			return exchangeResult{err: err}
		}

		if err := ctx.Err(); err != nil {
			return exchangeResult{err: err}
		}

		response, err := c.exchange(ctx, operation, payload)
		if err == nil {
			if decodeErr := decode(response.Payload); decodeErr != nil {
				err = c.failProtocol(decodeErr)
			}
		}

		return exchangeResult{message: response, err: err}
	}()
	c.report(ctx, operation, started, result.message.Observations, result.err)

	return result.err
}

func (c *Client) failProtocol(err error) error {
	return c.stop(fmt.Errorf("%w: %w", ErrProtocol, err))
}

func (c *Client) report(ctx context.Context, operation string, started time.Time, observations []kalkan.OperationObservation, err error) {
	ctx = context.WithoutCancel(ctx)

	if c.observer != nil {
		for _, observation := range observations {
			c.observer(ctx, observation)
		}
	}

	if c.logger != nil {
		level, class := slog.LevelDebug, "none"
		if err != nil {
			level, class = slog.LevelError, "operation_failure"
		}

		if errors.Is(err, context.Canceled) {
			class = "canceled"
		}

		if errors.Is(err, context.DeadlineExceeded) {
			class = "deadline_exceeded"
		}

		if errors.Is(err, ErrWorkerFailed) {
			class = "worker_failure"
		}

		c.logger.LogAttrs(ctx, level, "kalkan isolated call completed", slog.String("operation", operation), slog.String("error_class", class), slog.Duration("total_duration", time.Since(started)))
	}
}

// Close closes the session and waits for the worker to exit, without a timeout.
// Use [Client.CloseContext] to cancel a shutdown that may be stuck in native code.
func (c *Client) Close() error { return c.CloseContext(context.Background()) }

// CloseContext always starts closing and rejects new operations, even when ctx
// is already canceled. Cancellation of any waiting CloseContext forcibly stops
// the worker and ends shutdown with that context's error. Without cancellation,
// shutdown waits for the active call and graceful worker exit. Concurrent and
// repeated calls share the shutdown result; a completed result takes precedence
// over cancellation. There is no internal timeout.
func (c *Client) CloseContext(ctx context.Context) error {
	if c == nil || c.gate == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()
	if c.closing == nil {
		shutdownCtx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))

		c.closing = &closeState{done: make(chan struct{}), cancel: cancel}
		if err := ctx.Err(); err != nil {
			cancel(err)
		}

		go c.shutdown(shutdownCtx, c.closing)
	}

	closing := c.closing
	c.mu.Unlock()

	select {
	case <-closing.done:
		return closing.err
	default:
	}

	select {
	case <-closing.done:
		return closing.err
	case <-ctx.Done():
		closing.cancel(ctx.Err())
		<-closing.done

		return closing.err
	}
}

func (c *Client) shutdown(ctx context.Context, closing *closeState) {
	defer closing.cancel(nil)

	started := time.Now()

	err := c.gracefulShutdown(ctx, closing)
	// Only this shutdown's cancellation returns the sentinel directly. A prior
	// worker failure or a decoded native Close error can wrap a context error.
	if err == context.Canceled { //nolint:errorlint // Distinguish shutdown cancellation from wrapped operation failures.
		err = context.Cause(ctx)
		_ = c.stop(err)
	}

	c.mu.Lock()
	closing.err = err
	close(closing.done)
	c.mu.Unlock()
	c.report(ctx, opClose, started, closing.observations, err)
}

func (c *Client) gracefulShutdown(ctx context.Context, closing *closeState) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.gate:
	}

	defer func() { c.gate <- struct{}{} }()

	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	terminal := c.terminal
	c.mu.Unlock()

	if terminal != nil {
		_ = c.stop(terminal)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.exited:
			return terminal
		}
	}

	response, err := c.exchange(ctx, opClose, nullPayload())
	closing.observations = response.Observations

	if err == nil && !response.Payload.isNull() {
		err = c.failProtocol(errors.New("invalid Close acknowledgement"))
	}

	if err != nil {
		_ = c.stop(err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.exited:
			return err
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.exited:
	}

	c.mu.Lock()
	processErr := c.waitErr
	c.mu.Unlock()

	if processErr != nil {
		return c.stop(processErr)
	}

	return nil
}
