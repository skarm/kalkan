package kalkan

import "errors"

var (
	// ErrInvalidInput identifies invalid caller input or invalid data from the native library.
	// Validation and parse errors wrap this error.
	ErrInvalidInput = errors.New("kalkan: invalid input")

	// ErrClosed indicates a method call after client shutdown starts.
	ErrClosed = errors.New("kalkan: client is closed")

	// ErrUnavailable indicates that the current build or platform has no native KalkanCrypt loader.
	ErrUnavailable = errors.New("kalkan: native KalkanCrypt loader is unavailable")
)
