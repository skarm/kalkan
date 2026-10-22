// Package ckalkan provides a low-level Go binding for libkalkancryptwr.
//
// KalkanCrypt stores keys, XML state, network configuration, and errors in the native library.
// The package allows one active [Client] per process and serializes public method calls.
// Share the pointer from [New].
// Do not copy Client values.
//
// Use the root kalkan package for application code.
// Use ckalkan for direct control over native flags, buffers, and status codes.
//
// [New] requires [WithLibrary].
// Methods do not accept context.Context.
// Cancellation cannot stop a lock wait or active native call.
// Keep input byte slices unchanged until the method returns.
//
// For APIs with output capacities, the client retries with geometric buffer
// growth under [WithMaxBufferSize].
// Signature estimates select the initial capacity within that limit.
// Estimates do not establish the required output size.
//
// KC_GetTokens and KC_GetCertificatesList receive no output capacity.
// [WithListBufferSize] and retries cannot bound their native writes.
//
// [KalkanError] reports native operation failures.
// [ErrorCodeOf] extracts native status codes through wrapped errors.
// [OutputBufferLimitError] reports output that cannot fit within the
// configured hard limit.
//
// Real native calls require a platform driver.
// Builds without a native loader compile stubs.
// On those builds, New returns [ErrUnavailable] after the caller supplies a library path.
// Zero-value Client methods also return ErrUnavailable on those builds.
package ckalkan
