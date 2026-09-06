# KalkanCrypt for Go

[Русская версия](README_RU.md)

[![CI](https://github.com/skarm/kalkan/actions/workflows/ci.yml/badge.svg)](https://github.com/skarm/kalkan/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/skarm/kalkan.svg)](https://pkg.go.dev/github.com/skarm/kalkan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

Go wrapper for KalkanCrypt. The root package exposes typed operations over the lower-level `ckalkan` binding.

## Compatibility

- Go 1.26+
- `linux/amd64` with `CGO_ENABLED=1`
- `windows/amd64`

Native CI exercises `libkalkancryptwr-64.so.2.0.13`.

`windows/386`, Linux with `CGO_ENABLED=0`, and other targets compile against the unsupported driver and return `ErrUnavailable`.

Obtain the SDK from the [NCA RK developer portal](https://pki.gov.kz/en/to-developers/). `WithLibraryPath` requires an absolute path to the x64 `.so` or DLL.

## Install

```sh
go get github.com/skarm/kalkan@latest
```

## Packages

- [`github.com/skarm/kalkan`](https://pkg.go.dev/github.com/skarm/kalkan): typed CMS, XML, WS-Security, hashing, ZIP, certificate, OCSP/TSA, proxy, and logging APIs
- [`github.com/skarm/kalkan/ckalkan`](https://pkg.go.dev/github.com/skarm/kalkan/ckalkan): ABI-level binding with native flags, encodings, and buffer controls
- [`github.com/skarm/kalkan/isolated`](isolated): opt-in local worker processes with independent SDK sessions and cancellation by process termination

Use `ckalkan` when the root package does not expose the required operation. Use it to build a custom high-level layer over KalkanCrypt with its own request types, validation, buffer policies, logging, or error mapping.

`ckalkan` closely mirrors the native API. Calling code owns native flags, encodings, buffer sizing, and status-code handling; it must also account for client lifecycle, ABI constraints, and any required process isolation.

### Low-level output buffers

The `ckalkan` buffer options cover two ABI shapes:

- `WithListBufferSize` sets the initial allocation for `KC_GetTokens` and `KC_GetCertificatesList`; the default is 1 MiB. In the tested Linux SDK 2.0.13, these functions receive no byte-capacity argument, and `tk_count` and `cert_count` are output item counts. The option controls allocation size but does not bound the native write.
- `WithBufferSize` sets the global initial capacity for length-aware output calls when a request does not specify its own capacity. Without this option, operation-specific defaults are 32 bytes for raw SHA-256, GOST 34.11-95, and GOST 34.11-2015-256 hashes; 64 bytes for raw GOST 34.11-2015-512; 256 bytes for Base64/PEM hash output with any algorithm; 128 bytes for other raw hash algorithms; 4 KiB for metadata, 8 KiB for certificates, and 64 KiB for signatures and generic outputs. Attached CMS uses the in-memory input or file size plus a conservative signature reserve; CMS Base64 and PEM expansion is included. Signed XML/WSSE uses the in-memory XML size plus the same reserve (`KC_IN_FILE` is not supported by these two SDK calls). These calls initialize an output-length parameter with the capacity and retry after `KCR_BUFFER_TOO_SMALL`.
- Every output buffer has a 64 MiB hard limit by default (`ckalkan.DefaultMaxOutputBufferSize`). `WithMaxBufferSize(0)` restores that safe default; a positive value deliberately selects a smaller or larger limit, up to the native C `int` maximum of 2^31-1 bytes. A negative value makes `New` return `ErrInvalidOutputBufferSize`. If native code reports that more than the active limit is required, the wrapper returns a typed `OutputBufferLimitError` containing the operation, requested size, and applied limit before retrying with or allocating the oversized capacity.

On Linux, `ZipConVerify` requires a 64 KiB safety allocation because SDK 2.0.13 can write past a smaller reported capacity. If an explicit hard limit is below that safety minimum, the call fails before entering the native library.

Positive `WithBufferSize` and `WithListBufferSize` values are normalized to at least 64 KiB. Positive `WithMaxBufferSize` values are honored exactly up to the C `int` ABI maximum. A smaller hard limit may prevent an operation from using its usual initial capacity; the 64 MiB default is a security and availability boundary, not an indication that an operation should normally use that much memory.

The allocation limit also bounds wrapper retries for `KC_GetTokens` and `KC_GetCertificatesList`, but it does not fix their separate ABI risk: those two functions receive no byte-capacity argument, so even the initial native write cannot be bounded by this option.

An apparently successful list result that occupies the entire allocation without a NUL terminator is treated as potentially truncated and retried with a larger allocation.

## Client usage

```go
import (
	"context"
	"errors"
	"os"

	"github.com/skarm/kalkan"
)

func hash(ctx context.Context) (digest *kalkan.Digest, err error) {
	client, err := kalkan.Open(ctx,
		kalkan.WithLibraryPath(os.Getenv("KALKANCRYPT_LIBRARY")),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, client.Close())
	}()

	return client.Hash(ctx, kalkan.HashRequest{
		Algorithm: kalkan.GOST2015_512,
		Data:      kalkan.Bytes([]byte("document payload")),
	})
}
```

`Open` configures these production endpoints by default:

- TSA: `http://tsp.pki.gov.kz:80`
- OCSP: `http://ocsp.pki.gov.kz`

The corresponding test endpoints are:

- TSA: `http://test.pki.gov.kz/tsp/`
- OCSP: `http://test.pki.gov.kz/ocsp/`

Configure the test pair explicitly when required:

```go
client, err := kalkan.Open(ctx,
	kalkan.WithLibraryPath(os.Getenv("KALKANCRYPT_LIBRARY")),
	kalkan.WithTSAURL("http://test.pki.gov.kz/tsp/"),
	kalkan.WithOCSPURL("http://test.pki.gov.kz/ocsp/"),
)
```

`WithTSAURL` and `WithOCSPURL` can be set independently. Signing operations require `LoadKeyStore`; see the [package examples](example_test.go).

`Open` always configures a nonempty TSA URL; `WithTSAURL("")` is invalid. The `Timestamp` fields of `SignCMSRequest` and `SignHashRequest` request timestamp tokens independently of this URL setup. The SDK setter `KC_TSASetUrl` returns no status, so a successful setup or `ckalkan.Client.SetTSAURL` call does not confirm that the SDK accepted the URL or that the TSA server is reachable.

## Runtime model

KalkanCrypt state is process-global. Native calls are serialized individually. A `LoadKeyStore` call followed by signing is not atomic: other calls can run between them. Callers sharing a client across different key stores must synchronize the entire load-and-sign sequence or use separate processes.

Keep and share the client pointers returned by `Open` or `ckalkan.New`; do not copy client structs. `go vet` detects accidental copies, including copies of the low-level `ckalkan.Client`.

After a successful native `LoadKeyStore`, the client restores every certificate successfully loaded through `WithTrustedCertificate` or `LoadTrustedCertificate` before allowing another operation to run. Certificate bytes are copied after their initial load and retained until `Close`; certificate files must remain available and unchanged for subsequent key-store loads. Restoration finishes even if the context is canceled after the native key-store load starts. A restoration error reports partial success: the key store has changed, trust may be incomplete, and a later `LoadKeyStore` retries restoration. The key-store change is not rolled back.

`context.Context` can cancel waiting for the root client's call gate. It cannot interrupt the low-level process mutex wait, library loading, or an active KalkanCrypt call, including `Init`. Cleanup after failed or canceled `Open` also waits without a context.

`Client.Close()` waits for the active call and can block indefinitely. `Client.CloseContext(ctx)` stops the caller’s wait on `ctx.Err()`, leaves the client in closing state, and rejects new operations. Enforce hard native-call deadlines with process isolation. Closing starts even if the context is already canceled. Once closing finishes, repeated calls return the saved result.

On Windows, `LoadLibraryExW` uses `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`. The current working directory and `PATH` are excluded. Narrow `char*` arguments are encoded as UTF-8 with a terminating NUL.

## Optional process isolation

Import `github.com/skarm/kalkan/isolated` to run each client in a dedicated child process. The application provides its own worker mode in the same executable; no separate worker command or build is needed. The ordinary `kalkan.Open` keeps its in-process behavior.

At the start of `main`, before parsing application flags or starting services:

```go
if len(os.Args) == 2 && os.Args[1] == "--kalkan-worker" {
	if err := isolated.RunWorker(context.Background()); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
```

The parent starts a copy of its own executable. `WorkerArgs` selects the branch above and is passed directly, without a shell. Keep application startup out of `init` functions, which also execute in child processes. `RunWorker` redirects standard streams to null; exit immediately when it returns, even on success, because a native call may still be stuck.

In the application's normal execution path:

```go
executable, err := os.Executable()
if err != nil {
	return err
}
client, err := isolated.Open(ctx, isolated.Config{
	WorkerPath:  executable,
	WorkerArgs:  []string{"--kalkan-worker"},
	LibraryPath: "/opt/kalkan/libkalkancryptwr-64.so.2.0.13",
})
if err != nil {
	return err
}
defer client.CloseContext(ctx)

digest, err := client.Hash(ctx, kalkan.HashRequest{
	Algorithm: kalkan.SHA256,
	Data:      kalkan.Bytes([]byte("document payload")),
})
```

A single `.so`/DLL file can serve multiple workers: each process owns its keys, trust and mutable SDK state. Independent clients run in parallel; synchronize multi-call load-and-sign sequences within a shared client.

The [complete examples](isolated/example_test.go) show SHA-256 file hashing and CMS signing with verification. Each includes its worker branch, configuration, error handling and shutdown. To run either example, copy its function into your application as `main` (with `package main` and the required imports), adjust the input/certificate paths, set `KALKANCRYPT_LIBRARY`, and build the application on a platform supported by the SDK. For signing, also set `KALKAN_KEY_PASSWORD` and use a currently valid certificate with its CA chain. The CMS output path must not exist. No separate worker executable is needed.

The package implements all 21 root client operations with the existing request/result types. `Config` carries the library settings instead of serializing `kalkan.Option` closures. `TSAURL` and `OCSPURL` are optional pointers: nil selects the root default. `Logger` and `Observer` run in the parent.

The worker exchanges frames over two anonymous pipes: a binary header followed by raw binary blocks. Operation fields, configuration, errors and observations use an explicit binary layout; byte inputs and results are sent directly. `kalkan.File(path)` transfers only the path; the parent does not read the file. The sender borrows byte slices until the call returns, including waiting for its I/O goroutine to stop on cancellation. Its standard streams are redirected to null before SDK loading, so native stdout cannot corrupt responses. No TCP socket or token is used. Byte inputs, encodings, explicit empty sources and opaque string bytes survive transport. Errors preserve their original text and `errors.Is` matches for package, context and `io/fs` sentinels. Native `ckalkan.KalkanError` and `ckalkan.OutputBufferLimitError` remain inspectable with `errors.As`; `ckalkan.ErrorCodeOf` also works. Other concrete error types are not reconstructed.

`Open`, operations and `CloseContext` use only the supplied context, with no internal timeouts. Set deadlines with `context.WithTimeout` or `context.WithDeadline`, or cancel explicitly; a context without a deadline can wait indefinitely. An operation's context covers its queue wait and exchange with the worker. Canceling startup's context after successful `Open` does not close the client. A canceled queued request leaves its worker alive; cancellation after transmission starts terminates it. Subsequent calls return `isolated.ErrWorkerFailed`, and recovery requires a new client. Calls are never automatically retried.

`Close()` waits for the active call and graceful worker exit without a timeout. Canceling any pending `CloseContext(ctx)` forcibly terminates the worker and ends the shared shutdown with `ctx.Err()`, including when another goroutine already called `Close()`. Concurrent and repeated close calls return the saved result; a completed result takes precedence over cancellation. Each started process is reaped. Go-side encoding, decoding and application callbacks cannot be preempted by context cancellation. Returned native observations run after the call gate is released, and Close observations run after the close result is published, allowing reentry.

IPC adds no limit to raw data size: frame and block lengths use 64-bit integers. The receiver reads bounded chunks as bytes arrive and joins them once after receiving the complete block; small blocks need no join. A truncated frame cannot allocate its entire declared body up front. Operations still consume and return complete byte slices, so this is not a streaming SDK API. Metadata is capped at 64 KiB and each frame at 1024 blocks. Input/output options and SDK constraints still apply; these do not bound total process memory.

Isolation separates memory and SDK sessions; the worker still has the application's filesystem, environment and network access. Relative paths use the worker's startup working directory. An interrupted operation may already have created output or contacted a TSA. Forced exit skips deferred cleanup, so output files or ZIP staging directories can remain; applications manage their output paths and recovery. Passwords and IPC data are copied in memory and cannot be zeroized by this package.

## Inputs and bounds

Operations use `Source` values:

- `kalkan.Bytes(data)`: raw in-memory bytes for payloads, XML, or already-decoded binary data; the operation selects the field-specific native flags
- `kalkan.Base64(data)`: in-memory input that already contains Base64 text; the constructor does not encode `data`
- `kalkan.PEM(data)`: an existing PEM representation; the constructor does not create the PEM envelope
- `kalkan.DER(data)`: an existing DER representation, used to select DER explicitly for CMS and certificate inputs
- `kalkan.File(path)`: a file path; supported operations forward it to KalkanCrypt, while `GetCertFromCMS` reads the file into memory

Supported variants are operation-specific.

A source encoding other than `EncodingAuto` takes precedence over request encoding fields and operation defaults. `Bytes`, `Base64`, `PEM`, and `DER` set explicit encodings; `File` starts with `EncodingAuto`. For example, `VerifyCMSRequest.Encoding: EncodingBase64` does not reinterpret a `Bytes` source as Base64. Use `Base64(encoded)` or explicitly restore fallback selection with `Bytes(encoded).WithEncoding(EncodingAuto)`.

The in-memory constructors neither copy nor transform the provided byte slice. Operation-specific validation may decode PEM or Base64 before the native call. On Linux and Windows, length-delimited in-memory inputs are normally passed directly to KalkanCrypt without an adapter copy. Base64 data passed to `SignData` and Base64 CMS signatures passed to `VerifyData`, `GetCertFromCMS`, and `GetTimeFromSig` receive an owned NUL-terminated copy because Linux SDK 2.0.13 reads these inputs as C strings despite accepting an explicit length; the logical length passed to the SDK is unchanged. Except for `GetCertFromCMS`, `File` forwards the original path after empty-path and NUL validation; the native adapter adds the C-string terminator required by `KC_IN_FILE`. Keep borrowed slices and referenced files unchanged until the call returns.

`WithMaxInputSize` caps high-level in-memory inputs and files read by `GetCertFromCMS`. It does not apply to files read directly by the SDK or native output buffers. Native output buffers have a 64 MiB hard limit by default (`kalkan.DefaultMaxOutputBufferSize`). `WithMaxOutputBufferSize(0)` restores that default; a positive value selects a smaller or larger limit (up to the native C `int` maximum), and a negative value makes `Open` return `ErrInvalidInput`. The option is forwarded to `ckalkan.WithMaxBufferSize`. Exceeding the active limit returns `ckalkan.OutputBufferLimitError` before an oversized retry or allocation.

Native binary outputs are returned strictly according to the SDK-reported `outLen`; zero bytes inside that range are preserved. The returned slice has `len` and `cap` limited to the logical result, so unused buffer capacity is not exposed. Byte-slice results are bounded views rather than copies: keeping a result alive also retains the successful native backing allocation, avoiding a second large allocation and copy. Known textual outputs use C-string semantics and end at the first NUL because some KalkanCrypt methods report a fixed-size block and leave unspecified bytes after the terminator.

`ErrInvalidInput` can describe invalid caller input or malformed data returned by the native library, including certificate parsing failures.

`KeyStore.Password` and `Proxy.Password` are strings. Go memory, KalkanCrypt state, and SDK-internal copies cannot be zeroized by this package.

## CMS and digest signing

CMS output is raw DER by default. Select `CMSOutputBase64` or `CMSOutputPEM` for text output.

`GetTimeFromSig` reads the timestamp of signer 0 (the first signer). The low-level `ckalkan.Client.GetTimeFromSig` method accepts an explicit signer index.

`GetCertFromCMS` returns the embedded signer certificates using the SDK's one-based certificate indices. Unlike `VerifyCMS`, this SDK operation accepts only container contents: the root method reads `File` sources into memory once and applies `WithMaxInputSize` while reading them. Certificate extraction does not verify the signature.

`SignHashRequest.Digest` is the precomputed digest. `DigestAlgorithm` describes how it was calculated; its zero value is `SHA256`. The wrapper checks the algorithm and digest length, but this field does not select the native signing algorithm. The digest must match the loaded signing key: for example, use `GOST2015_512` with the bundled GOST 2015 512-bit test keys. Linux SDK 2.0.13 derives the algorithm from the key and ignores the `Hash*` flags in `SignHash`. A wrong digest can have the expected length and still produce a CMS successfully; verify that CMS against the original payload.

## XML and WS-Security

`VerifyXML` delegates cryptographic verification to KalkanCrypt. For SOAP 1.1 and SOAP 1.2, `ExpectedBodyID` is required and the wrapper enforces:

- exactly one `ds:Signature`
- exactly one direct-child `ds:SignedInfo`
- exactly one SOAP Body that is a direct child of the Envelope and has the exact expected `wsu:Id`, without trimming whitespace
- a direct `ds:Reference` to `#ExpectedBodyID`
- the Body reference has either no `ds:Transforms`, or exactly one direct `ds:Transform` using Exclusive XML Canonicalization (`http://www.w3.org/2001/10/xml-exc-c14n#`)
- this transform may include one `InclusiveNamespaces` parameter with a `PrefixList` attribute; an empty list is allowed
- no duplicate matching `Id`, `ID`, or `id` attributes in any namespace; namespace declarations are excluded

XML operations accept `kalkan.Bytes`; file and pre-encoded sources are rejected.

`GetCertFromXML` returns one embedded certificate per signature in document order; it does not verify signatures or establish certificate trust. To avoid the SDK's ambiguous lookup by position or `Signature Id`, extraction uses a copy with unqualified `ds:Signature` `Id` attributes removed. The caller's XML is unchanged, and this copy is never used by `VerifyXML`.

Additional direct references may cover other WS-Security nodes. SOAP input must be UTF-8; one optional BOM at the start is accepted without changing the bytes passed to native verification. Non-SOAP XML accepts UTF-8 or an ASCII-compatible declared encoding when the prolog and root tag are ASCII.

The wrapper does not independently allowlist `CanonicalizationMethod`, `DigestMethod`, or `SignatureMethod`: the supported cryptographic algorithms depend on the installed KalkanCrypt version and repository fixtures do not establish a stable complete set. KalkanCrypt remains responsible for rejecting unsupported methods.

## Certificate validation

`TrustedCertificate.Type` is validated for both `Path` and `Data`, but its CA/intermediate/user role is forwarded to the SDK only for `Path`. The buffer-loading API receives `Data` and `Format` and has no role parameter.

`ValidateCertificateRequest.Mode` must be one of `CertificateValidationOCSP`, `CertificateValidationCRL`, or `CertificateValidationNone`. The zero value is invalid. `CertificateValidationNone` explicitly disables external revocation checks.

`CertificateValidation.OCSPResponse` is `nil` unless `ReturnOCSPResponse` is requested.

Certificate input supports DER, PEM, and base64; `kalkan.File` is rejected. PEM input must contain exactly one `CERTIFICATE` block. Explicit DER, PEM, and base64 inputs are normalized to PEM for the native validator; raw and auto sources retain their bytes and must already use an encoding the SDK accepts. `RevocationSource` is a CRL path in CRL mode and an OCSP URL override in OCSP mode.

`WithOCSPURL` and `WithTSAURL` override the package defaults. URL validation checks syntax but does not restrict the destination.

`WithEndpointPolicy(EndpointPolicy{AllowedHosts: []string{"tsa.example", "ocsp.example"}, RequireHTTPS: true})` optionally restricts both configured endpoints and per-request OCSP URLs. Set `WithTSAURL` and `WithOCSPURL` to addresses accepted by the policy. Hosts match exactly, ignoring case and a trailing DNS dot; `AllowedPorts` limits ports (empty means scheme-default ports), and IP literals require both `AllowIPAddresses` and an allowlist entry. Rejections return `ErrInvalidInput`. KalkanCrypt performs DNS resolution and redirects itself; the policy does not replace network egress controls.

With this policy, DNS names in both `AllowedHosts` and endpoint URLs must use ASCII. Use Punycode for internationalized names, for example `xn--bcher-kva.example`; Unicode names are rejected without automatic IDNA conversion. List IPv6 literals without brackets in `AllowedHosts`, for example `2001:db8::1`, and use brackets in URLs, for example `https://[2001:db8::1]/`. IPv6 zone identifiers are not supported.

Use `X509CertificateGetInfoFields` on metadata hot paths. `CertificateInfo` exposes IIN, BIN, subject type, and recognized NCA roles when the corresponding fields are requested.

## ZIP containers

`SignZIPRequest.OutputPath` must end with `.zip`, case-insensitively. Existing requested and normalized output paths are rejected before the native call. KalkanCrypt creates the file without an atomic create-if-absent guarantee.

`WithAtomicZIPOutput()` enables atomic publication of completed ZIP output without replacing an existing file. KalkanCrypt writes into a private temporary directory next to the output; temporary files are removed when the operation returns. This option requires hard-link support and an output directory controlled by the application. It is disabled by default.

ZIP input paths are forwarded after empty-path and NUL validation. Keep the files unchanged until each operation returns.

`VerifyZIP` and `ExtractZIPSignerCertificate` are independent. Certificate extraction does not verify the ZIP signature. Call `VerifyZIP` first when both results are required.

## Diagnostics

`WithObserver(func(ctx context.Context, event kalkan.OperationObservation) { ... })` reports native-call attempts, including setup during `Open` and final `Close`. `QueueWait`, `NativeDuration`, and `TotalDuration` measure the call helper; validation before it and diagnostic callbacks are excluded. `NativeDuration` includes checks and lock waits inside the low-level call callback. `ErrorClass`, `NativeCode`, and `Expected` describe the outcome without raw error text or input/output data. Returned errors are unchanged. Certificate enumeration endings and absent optional properties retain their expected status.

Observers run synchronously after the native gate is released, may run concurrently, and must not panic. A slow observer delays its caller; `Close` publishes its saved result before invoking diagnostics and may return first. `WithLogger` records the same safe metadata and never records raw SDK error messages, paths, URLs, or payloads. Timings are not collected when both logger and observer are absent.

## Checks

```sh
make check
```

```sh
KALKANCRYPT_LIBRARY=/opt/kalkan/lib/libkalkancryptwr-64.so \
KALKANCRYPT_SDK_ASSETS=./testdata \
LD_LIBRARY_PATH=/opt/kalkan/lib \
make test-native
```

`make docker-test` expects the Linux SDK libraries under `.local/kalkancrypt/lib/linux/`.

On Windows:

```powershell
$env:KALKANCRYPT_LIBRARY = "C:\KalkanCrypt\KalkanCrypt.dll"
go test ./...
```

Historical test assets and their public fixture password are described in [`testdata/README.md`](testdata/README.md).

## Project policies

- [Contributing](.github/CONTRIBUTING.md)
- [Security policy](.github/SECURITY.md)
- [Code of Conduct](.github/CODE_OF_CONDUCT.md)
- [MIT License](LICENSE.md)

The repository license does not grant rights to KalkanCrypt SDK binaries.
