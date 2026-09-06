package kalkan

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

// OperationObservation describes one native-call attempt, including setup calls
// during Open and the final Close. Input validation before the call helper does
// not produce an observation. Fields contain no request or response payloads,
// paths, URLs, or raw error text.
type OperationObservation struct {
	// Operation names the native-call attempt, such as Hash or SignXML.
	Operation string
	// QueueWait measures waiting to enter the client native-call gate.
	QueueWait time.Duration
	// NativeDuration measures the low-level call callback, including its checks
	// and lock waits. It is zero if that callback was not entered.
	NativeDuration time.Duration
	// TotalDuration measures the call helper through gate release, excluding
	// observer and logger execution and validation before the helper.
	TotalDuration time.Duration
	// ErrorClass is a diagnostic category: none, expected_status, native_failure,
	// output_limit, canceled, deadline_exceeded, closed, invalid_input,
	// unavailable, or operation_failure. It does not change the returned error.
	ErrorClass string
	// NativeCode is zero when the error has no native code.
	NativeCode ckalkan.ErrorCode
	// Expected marks an SDK status accepted by the enclosing operation, such
	// as the end of certificate enumeration after at least one certificate.
	Expected bool
}

// Observer receives native-call timings and safe outcome metadata. Calls are
// synchronous after gate release and may run concurrently or reenter Client.
// A slow callback delays its caller, but does not hold the native gate. The
// Close callback runs in the closing goroutine after the saved close result is
// ready, so Close can return before that callback finishes. Observers should
// return promptly and must not panic.
type Observer func(context.Context, OperationObservation)

func reportOperation(c *Client, ctx context.Context, operation string, start time.Time, queueWait, nativeDuration time.Duration, err error, expectedCodes ...ckalkan.ErrorCode) {
	observation := OperationObservation{
		Operation:      operation,
		QueueWait:      queueWait,
		NativeDuration: nativeDuration,
		TotalDuration:  time.Since(start),
	}
	observation.NativeCode, _ = ckalkan.ErrorCodeOf(err)

	for _, code := range expectedCodes {
		if code != 0 && observation.NativeCode == code {
			observation.Expected = true
			break
		}
	}

	observation.ErrorClass = operationErrorClass(err, observation.NativeCode, observation.Expected)
	if c.config.observer != nil {
		c.config.observer(ctx, observation)
	}

	logNativeCall(c, ctx, observation)
}

func operationErrorClass(err error, code ckalkan.ErrorCode, expected bool) string {
	var outputLimit *ckalkan.OutputBufferLimitError

	switch {
	case err == nil:
		return "none"
	case expected:
		return "expected_status"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.As(err, &outputLimit):
		return "output_limit"
	case code != 0:
		return "native_failure"
	case errors.Is(err, ErrClosed):
		return "closed"
	case errors.Is(err, ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	default:
		return "operation_failure"
	}
}

func logNativeCall(c *Client, ctx context.Context, observation OperationObservation) {
	if c.logger == nil {
		return
	}

	level := slog.LevelDebug
	message := "kalkan native call completed"

	if observation.ErrorClass != "none" && !observation.Expected {
		level = slog.LevelError
		message = "kalkan native call failed"
	}

	if !c.logger.Enabled(ctx, level) {
		return
	}

	attrs := []slog.Attr{
		slog.String("operation", observation.Operation),
		slog.Duration("queue_wait", observation.QueueWait),
		slog.Duration("native_duration", observation.NativeDuration),
		slog.Duration("total_duration", observation.TotalDuration),
		slog.String("error_class", observation.ErrorClass),
	}
	if observation.NativeCode != 0 {
		attrs = append(attrs, slog.String("native_code", observation.NativeCode.Hex()))
	}

	c.logger.LogAttrs(ctx, level, message, attrs...)
}
