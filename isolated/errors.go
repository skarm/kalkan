package isolated

import (
	"errors"
	"fmt"
)

var (
	// ErrWorkerFailed marks a terminated or unusable worker. Create a new client;
	// operations are never replayed automatically.
	ErrWorkerFailed = errors.New("kalkan isolated: worker failed")
	// ErrProtocol marks an incompatible or malformed worker message.
	ErrProtocol = errors.New("kalkan isolated: invalid protocol message")
)

// WorkerError reports a terminal worker failure. After a request starts, failure
// does not imply rollback: file output or a remote timestamp may already exist.
// It matches [ErrWorkerFailed] through [errors.Is] and unwraps to Cause.
type WorkerError struct {
	// Cause is the underlying process, transport, or cancellation error.
	// It may be nil when the worker exits without an error status.
	Cause error
}

// Error returns the worker failure message, including Cause when present.
func (e *WorkerError) Error() string {
	if e == nil || e.Cause == nil {
		return ErrWorkerFailed.Error()
	}

	return fmt.Sprintf("%s: %v", ErrWorkerFailed, e.Cause)
}

// Unwrap returns Cause, or nil if e is nil.
func (e *WorkerError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Cause
}

// Is reports whether target is [ErrWorkerFailed].
func (e *WorkerError) Is(target error) bool { return target == ErrWorkerFailed }
