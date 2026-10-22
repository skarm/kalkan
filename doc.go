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
// KalkanCrypt shares native state across the process.
// The client serializes individual native calls.
// Synchronize sequences that load a key store and then sign with that key
// store.
// Context cancellation stops a wait for the client call gate.
// It cannot interrupt low-level mutex waits or active native calls.
// [Open] cannot cancel library loads or cleanup.
//
// Use process isolation when native calls require hard deadlines.
// The isolated package provides a client with a separate worker process.
//
// OCSP uses KalkanCrypt by default.
// [WithCustomOCSP] enables Go HTTP requests and response verification after
// native chain validation.
// The Go HTTP exchange respects context cancellation and [WithOCSPTimeout].
//
// [Open] requires [WithLibraryPath] with an absolute path to the native
// library.
// The package cannot erase passwords from Go strings.
package kalkan
