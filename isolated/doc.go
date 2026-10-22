// Package isolated provides a Kalkan client with a dedicated local worker
// process.
// SDK operations accept kalkan requests and return kalkan results.
// The corresponding kalkan.Client methods define their input and result
// contracts.
//
// Use the application's own executable as the worker:
//
//  1. Set Config.WorkerPath to the path from os.Executable.
//  2. Set Config.WorkerArgs to an argument that selects the worker entry point.
//  3. Check that argument before application services start.
//  4. Call [RunWorker] in the child process.
//  5. Exit the child process when RunWorker returns.
//
// Each child also runs init functions.
// Keep application startup actions outside init functions.
//
// Each client has its own SDK memory, loaded keys, and trust store.
// The client executes calls sequentially.
// Multiple clients can run in parallel with the same shared-library file.
// Isolation does not restrict filesystem, environment, network, or external
// SDK resources such as hardware tokens.
// Native code can crash or hang without damage to the parent process's
// memory.
//
// Two anonymous pipes carry frames with a length prefix, a binary header, and
// raw data blocks.
// The header encodes operation fields, configuration, errors, and
// observations.
// The protocol sends byte inputs and results directly.
// File sources transfer paths without a file read in the parent.
// Before the SDK loads, the worker duplicates protocol handles and redirects
// standard streams to null.
// The protocol requires no network listener, token, shell, or credential
// file.
//
// [Open], operations, and [Client.CloseContext] have no internal IPC
// timeouts.
// Each caller's context also limits the queue wait.
// Cancellation of the startup context after Open succeeds leaves the client
// alive.
// Cancellation during a queue wait leaves the worker alive.
// Cancellation after transmission starts kills the worker and permanently
// fails the client.
// Create a new client after a failure that returns [ErrWorkerFailed].
//
// The client does not restart workers or retry operations automatically.
// A failure after transmission does not prove that the operation had no
// effect.
// Output files or remote timestamps can already exist.
// A forced exit skips deferred cleanup, including cleanup of temporary ZIP
// directories.
// The application controls output paths and recovery.
//
// [Client.Close] waits without a timeout.
// Cancellation of any active [Client.CloseContext] wait kills the worker and
// ends shared shutdown with that context's error.
// Later close calls return the saved result.
// A supervisor calls Wait exactly once for each child that starts.
// Context cancellation cannot interrupt metadata encoding or application
// observers.
//
// OCSP uses KalkanCrypt by default.
// Config.CustomOCSP enables Go HTTP requests and OCSP signature verification
// in the worker.
// Config.OCSPTimeout separately limits the Go HTTP exchange.
//
// Frame and block lengths use 64-bit integers.
// IPC adds no raw data size limit.
// The receiver reads bounded chunks as bytes arrive and joins them once per
// complete block.
// Small blocks need no join.
// A truncated frame cannot force allocation of its full declared size.
// Each SDK operation still requires a complete byte slice.
//
// The protocol limits metadata to 64 KiB and each frame to 1024 blocks.
// A positive Config.MaxInputSize rejects oversized byte inputs in the parent.
// The worker's kalkan client also applies input and output options.
// These options do not bound total process memory.
//
// Keep source bytes unchanged until the method returns.
// The sender borrows them directly.
// On cancellation, it waits for its I/O goroutine before it returns
// ownership.
// The receiver allocates storage for raw blocks.
// The package copies passwords and request bytes into process memory and
// cannot erase all copies.
//
// File paths use the worker's startup directory, which it inherits from the
// parent.
// Keep input files unchanged until their operations return.
// Keep trusted certificate files available and unchanged for later key-store
// loads until the client closes.
package isolated
