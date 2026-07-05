// Package kalkan provides an application-level Go API for KalkanCrypt.
//
// The package supports hashing, CMS signatures, XML signatures, WS-Security
// signing, KalkanCrypt ZIP containers, certificate loading, and certificate
// validation. Inputs are described with typed request structs and Source
// values, so callers can choose in-memory data or native file paths without
// passing native KalkanCrypt flags through application code.
//
// KalkanCrypt keeps process-global native state. Client serializes native calls
// inside the current process. Context cancellation can stop waiting to enter a
// native call, including waiting for the serialization lock, but it cannot
// interrupt a KalkanCrypt call that has already entered the shared library.
// Server-side production services that need hard native-call deadlines should
// isolate KalkanCrypt outside this package, for example behind a worker process
// or process pool controlled by the application.
//
// Open requires WithLibraryPath with an absolute path to the native
// KalkanCrypt shared library. Dependent native libraries should be loaded only
// from trusted, read-only deployment directories. Passwords passed as Go strings
// cannot be zeroized by this package.
package kalkan
