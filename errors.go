package kalkan

import "errors"

var (
	// ErrInvalidInput is wrapped by validation errors raised before native calls.
	ErrInvalidInput = errors.New("kalkan: invalid input")

	// ErrClosed is returned when a Client method is called after Close.
	ErrClosed = errors.New("kalkan: client is closed")

	// ErrUnavailable is returned when the native KalkanCrypt loader is
	// unavailable for the current build/platform.
	ErrUnavailable = errors.New("kalkan: native KalkanCrypt loader is unavailable")
)
