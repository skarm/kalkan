// Package ckalkan provides a low-level Go binding for libkalkancryptwr.
//
// KalkanCrypt keeps loaded keys, XML state, network configuration, and error
// state in the native library. The package allows one active Client per process
// and serializes public method calls.
//
// Application code should prefer the root kalkan package. Use ckalkan when an
// integration needs native-level control over flags, buffer behavior, and
// KalkanCrypt status codes.
//
// [New] requires [WithLibrary]. Methods do not accept context.Context, so
// cancellation cannot stop a lock wait or an active native call.
// Callers must keep byte-slice inputs unchanged until a method returns.
//
// Length-aware output buffers retry with geometric capacity growth, bounded by
// [WithMaxBufferSize]. Signature output estimates select the initial capacity and
// are capped at the hard limit; they do not establish the required output size.
//
// KC_GetTokens and KC_GetCertificatesList do not receive output-buffer
// capacity. WithListBufferSize and retries cannot bound their native writes.
//
// Native operation failures are represented by [KalkanError]; [ErrorCodeOf]
// extracts their status through wrapped errors. [OutputBufferLimitError]
// reports an output that cannot fit within the configured hard limit.
//
// Real native calls require a platform driver. Builds without a native loader
// compile stubs; New returns ErrUnavailable after a library path is provided,
// and zero-value Client methods return ErrUnavailable on builds that have no
// native loader.
package ckalkan
