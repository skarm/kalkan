// Package kalkan provides an application-level Go API for KalkanCrypt.
//
// The package supports hashing, CMS signatures, XML signatures, WS-Security
// signing, KalkanCrypt ZIP containers, certificate loading, and certificate
// validation. Inputs are described with typed request structs and Source
// values, so callers can choose in-memory data or native file paths without
// passing native KalkanCrypt flags through application code.
// Source retains caller-provided byte slices; do not mutate them until the
// operation returns. File source paths are passed unchanged after validation.
//
// VerifyXML requires ExpectedBodyID for SOAP envelopes. Accepted non-SOAP input
// is passed to KalkanCrypt unchanged.
//
// Native calls are process-global and serialized. Context cancellation stops
// lock waits but cannot interrupt an active KalkanCrypt call; hard deadlines
// require process isolation.
//
// Open requires WithLibraryPath with an absolute path to the native KalkanCrypt
// library. Passwords passed as Go strings cannot be zeroized by this package.
package kalkan
