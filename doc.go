// Package kalkan provides an application-level Go API for KalkanCrypt.
//
// The package supports hashing, CMS signatures, XML signatures, WS-Security
// signing, KalkanCrypt ZIP containers, certificate loading, and certificate
// validation. Inputs are described with typed request structs and [Source]
// values, so callers can choose in-memory data or file paths without
// passing native KalkanCrypt flags through application code.
// Source retains caller-provided byte slices; do not mutate them until the
// operation returns. File source paths are passed unchanged after validation.
//
// [Client.VerifyXML] requires ExpectedBodyID for SOAP envelopes. Accepted
// non-SOAP input is passed to KalkanCrypt unchanged.
//
// [Open] selects a native backend with [WithLibraryPath] or a Java backend with
// [WithJavaProvider]. Each client serializes individual calls. Sequences such as
// [Client.LoadKeyStore] followed by signing require external synchronization.
//
// The native SDK has process-global state. Context cancellation stops waiting
// for the client call gate, but cannot interrupt library loading, low-level
// mutex waits, or active SDK calls. Hard deadlines require process isolation.
// Java clients own independent worker processes; canceling an active worker
// request terminates its session. Cleanup waits without a context.
// Passwords passed as Go strings cannot be zeroized by this package.
package kalkan
