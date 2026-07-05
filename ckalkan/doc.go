// Package ckalkan provides a low-level Go binding for libkalkancryptwr.
//
// The package is intentionally stateful: KalkanCrypt keeps loaded keys, XML
// state, network configuration, and last-error text globally inside the loaded
// .so. ckalkan therefore allows one active Client per process and serializes all
// public method calls through a process-wide lock.
//
// Application code should prefer the root kalkan package. Use ckalkan when an
// integration needs native-level control over flags, buffer behavior, and
// KalkanCrypt status codes.
//
// New requires WithLibrary with a verified KalkanCrypt library path. Dependent
// native libraries should be loaded only from trusted,
// read-only deployment directories. KalkanCrypt native calls are process-global
// and serialized; use separate worker processes for independent parallel
// sessions or stronger failure containment. ckalkan methods do not accept
// context.Context; caller-side context cancellation cannot cancel waiting for the
// low-level process lock or interrupt a KalkanCrypt call that has already
// entered the shared library.
//
// KC_GetTokens and KC_GetCertificatesList are not length-aware in the bundled
// KalkanCrypt header, so list-buffer retries are compatibility behavior, not an
// in-process memory-safety guarantee. Backend production services should run
// those methods in a worker process or process pool.
//
// Real native calls require a platform driver. Builds without a native loader
// compile stubs; New returns ErrUnavailable after a library path is provided,
// and zero-value Client methods return ErrUnavailable on builds that have no
// native loader.
package ckalkan
