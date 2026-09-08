// Package kalkan provides an application-level Go API for KalkanCrypt.
//
// The package supports hashes, CMS signatures, XML signatures, WS-Security
// signatures, ZIP containers, and certificates.
// Typed requests and [Source] values describe inputs without native flags.
// [Source] retains the caller's byte slices.
// Keep these slices unchanged until the operation returns.
// The client validates file paths and passes them to KalkanCrypt unchanged.
//
// [Client.VerifyXML] requires VerifyXMLRequest.ExpectedBodyID for SOAP
// envelopes.
// The client passes accepted non-SOAP input to KalkanCrypt unchanged.
//
// [Open] selects a native backend with [WithLibraryPath] or a Java backend with
// [WithJavaProvider]. Each client serializes individual calls. Sequences such as
// [Client.LoadKeyStore] followed by signing require external synchronization.
//
// The native SDK has process-global state. Context cancellation stops waiting
// for the client call gate, but cannot interrupt library loading, low-level
// mutex waits, or active SDK calls. Hard deadlines require process isolation.
// [WithCustomOCSP] optionally runs OCSP HTTP requests and response verification
// in Go after native chain validation. Its HTTP exchange honors cancellation
// and [WithOCSPTimeout]. By default, OCSP uses the native implementation.
// Java clients own independent worker processes; canceling an active worker
// request terminates its session. Cleanup waits without a context.
// Passwords passed as Go strings cannot be zeroized by this package.
package kalkan
