// Package isolated provides an opt-in Kalkan client backed by a dedicated local
// worker process. The application supplies its own worker entry point by calling
// [RunWorker] in a child process and exiting when it returns. Pass os.Executable
// as [Config.WorkerPath] and a worker-mode argument as [Config.WorkerArgs] to
// [Open]; no separate worker binary is required. Check the worker argument before
// starting application services, and keep init functions free of application
// startup side effects because they also run in each child.
// SDK operations accept kalkan request types and return kalkan result types.
// Their input and result contracts follow the corresponding kalkan.Client
// methods; this package adds the process lifetime and cancellation behavior
// described below. OCSP remains native by default; [Config.CustomOCSP] enables Go
// HTTP requests and OCSP signature verification in the worker.
//
// Each client has its own SDK address space, loaded keys and trust store. Calls
// in one client are sequential; multiple clients can run in parallel using one
// shared-library file. Isolation does not restrict the worker's filesystem,
// environment, network access, or external SDK resources such as hardware tokens.
//
// Two anonymous pipes carry length-prefixed frames with a binary header and raw
// data blocks. Operation fields, configuration, errors and observations are
// encoded explicitly in binary. Byte inputs and results are sent directly.
// File sources transfer the path, without reading the file in the parent.
// Before loading the SDK, the worker duplicates the protocol handles and
// redirects its standard streams to null. No listening socket, token, shell,
// or credential file is used.
// Native code can crash or hang without corrupting the parent process's memory.
//
// Open, operation calls and CloseContext have no internal IPC timeouts; their
// caller's context includes queue waiting. When [Config.CustomOCSP] is enabled,
// [Config.OCSPTimeout] separately bounds the worker's Go OCSP HTTP exchange.
// Canceling the startup context after Open succeeds leaves the client alive.
// A queued cancellation leaves the worker alive; cancellation after transmission
// starts kills it. A killed or crashed client returns [ErrWorkerFailed] on
// subsequent operations and must be replaced.
// There is no automatic restart or retry. A failure after transmission does not
// prove the operation had no effect: files or timestamp requests may already
// exist. Forced exit skips deferred cleanup, including ZIP staging-directory
// cleanup. Applications remain responsible for output paths and recovery.
//
// [Client.Close] waits without a timeout. Canceling any waiting
// [Client.CloseContext] forcibly terminates the worker and ends the shared
// shutdown with that context's error. Subsequent close calls return the saved
// result. A supervisor calls Wait exactly once to reap each started child.
// Metadata encoding and application observers cannot be preempted by context
// cancellation. Frame and block lengths use 64-bit integers; IPC adds no raw
// data size limit. The receiver reads bounded chunks as bytes arrive and joins
// them once after the complete block is received. Small blocks need no join.
// This avoids allocating the declared size of a truncated frame, but operations
// still require a complete byte slice; this is not a streaming SDK API.
// Metadata is capped at 64 KiB and each frame at 1024 blocks.
// MaxInputSize rejects oversized byte inputs in the
// parent when explicitly configured. Input/output options are passed to the
// worker's kalkan client; these do not bound total process memory.
//
// Source bytes must remain unchanged until the method returns. The sender
// borrows them directly and joins its I/O goroutine on cancellation before
// returning ownership; the receiver allocates storage for the raw blocks. File
// paths use the worker's inherited startup working directory; keep files
// unchanged while operations use them. Trusted certificate files must remain
// unchanged and available for later key-store loads. Passwords and request bytes
// are copied into process memory and cannot be zeroized here.
package isolated
