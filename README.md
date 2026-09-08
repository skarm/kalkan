# KalkanCrypt for Go

[Русская версия](README_RU.md)

[![CI](https://github.com/skarm/kalkan/actions/workflows/ci.yml/badge.svg)](https://github.com/skarm/kalkan/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/skarm/kalkan.svg)](https://pkg.go.dev/github.com/skarm/kalkan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

Go wrapper for KalkanCrypt. The root package exposes typed operations over the native `ckalkan` binding and an optional Java backend for hashing, CMS, XML/WS-Security, ZIP and certificate operations on macOS.

## Compatibility

- Go 1.26+
- Native backend: `linux/amd64` with `CGO_ENABLED=1`, or `windows/amd64`
- Java backend: JDK 17+ and the NCA RK Java provider JAR; tested on `darwin/arm64` with JDK 17 and 26 and provider 0.7.5, without a native library or cgo

Native CI exercises `libkalkancryptwr-64.so.2.0.13`.

The native backend returns `ErrUnavailable` on `windows/386`, Linux with `CGO_ENABLED=0`, and other unsupported native targets. Select the Java backend explicitly with `WithJavaProvider` to use its supported operations on macOS.

Obtain the SDK from the [NCA RK developer portal](https://pki.gov.kz/en/to-developers/). `WithLibraryPath` requires an absolute path to the x64 `.so` or DLL.

## Install

```sh
go get github.com/skarm/kalkan@latest
```

## macOS: Java backend

Obtain `knca_provider_jce_kalkan-0.7.5.jar` from the SDK's `Java/provider` directory and install a JDK 17 or later. The vendor JAR is not included in this module. `WithJavaProvider` requires an absolute JAR path and cannot be combined with `WithLibraryPath`. `WithJavaExecutable` accepts an executable path or name; its default is `java` from `PATH`. A JDK is required: a small bootstrap compiles the embedded Java source tree through the standard compiler API and starts the worker in the same JVM. No separate `javac` executable or build tool is needed.

The public client handles input validation, serialization of calls and diagnostics through the backend contract in [`backend.go`](backend.go). [`backend_native.go`](backend_native.go) owns native trust restoration; [`backend_java.go`](backend_java.go) binds each Java operation to its request context and maps errors. The Go bridge in `internal/javakalkan` owns process IPC, HTTP and bounded file input. The [Java worker](internal/javakalkan/worker/README.md) has a separate source tree and separates keys, certificate validation, CMS and XML. Java SDK tests live beside the backend in `internal/javakalkan/*_sdk_test.go`, in the external `javakalkan_test` package using the public API. SDK-independent tests use the internal package.

Use the root `kalkan.Open` API; `ckalkan` and `isolated` remain native backends. This example loads a PKCS#12 key, computes a hash, signs an attached CMS, and verifies it with explicit CA trust:

```go
import (
	"context"
	"errors"

	"github.com/skarm/kalkan"
)

func cmsRoundTrip(ctx context.Context, password string, payload []byte) (
	digest *kalkan.Digest, result *kalkan.Verification, err error,
) {
	client, err := kalkan.Open(ctx,
		kalkan.WithJavaProvider("/opt/kalkan/knca_provider_jce_kalkan-0.7.5.jar"),
		kalkan.WithJavaExecutable("java"),
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{
			Path: "/opt/kalkan/certs/root.cer", Type: kalkan.CertificateCA,
		}),
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{
			Path: "/opt/kalkan/certs/intermediate.cer", Type: kalkan.CertificateIntermediate,
		}),
	)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	if err = client.LoadKeyStore(ctx, kalkan.KeyStore{
		Type: kalkan.PKCS12, Path: "/opt/kalkan/keys/signing.p12", Password: password,
	}); err != nil {
		return nil, nil, err
	}
	digest, err = client.Hash(ctx, kalkan.HashRequest{
		Algorithm: kalkan.GOST2015_512, Data: kalkan.Bytes(payload),
	})
	if err != nil {
		return nil, nil, err
	}
	signed, err := client.SignCMS(ctx, kalkan.SignCMSRequest{
		Data: kalkan.Bytes(payload), IncludeCertificate: true,
	})
	if err != nil {
		return digest, nil, err
	}
	result, err = client.VerifyCMS(ctx, kalkan.VerifyCMSRequest{
		Signature: kalkan.DER(signed.Data), SignerID: 1,
	})
	return digest, result, err
}
```

The provider JAR supports `Hash` with SHA-256 and all three exposed GOST algorithms, PKCS#12 loading, `SignCMS`, `SignHash`, `VerifyCMS`, `GetTimeFromSig`, trusted-certificate loading, `ValidateCertificate`, `GetCertFromCMS`, `X509ExportCertificateFromStore`, `X509CertificateGetInfo` and `X509CertificateGetInfoFields`.

`CertificateInfo.SignatureAlgorithm` uses the native SDK's `signatureAlgorithm=<name>(<OID>)` format for known signature algorithms, including RSA and GOST. The Java backend preserves an unknown algorithm as its dotted OID instead of inventing a name. Reading this metadata does not verify the certificate signature.

CMS signing supports attached and detached signatures and DER, Base64, or PEM output. To add a signer, pass an in-memory DER/Base64/PEM CMS in `SignCMSRequest.ExistingSignature`, supply the same payload in `Data`, and match its `Detached` setting. Existing signatures, trust and revocation are verified before the new signer is added; existing signer records, certificates and CRLs are preserved. For append operations, Base64/PEM payloads, including files, are decoded in Go before the backend call; `WithMaxInputSize` also bounds these encoded files. For detached verification, set `Detached: true` and supply the original payload as `Data`. `VerifyCMS` verifies all primary signers; `SignerID` only selects the certificate returned in `SignerCert` (`0`: none, `1`: first). Attached verification returns the payload for in-memory signature inputs; file and detached verification leave `Data` empty.

`Timestamp: true` in `SignCMSRequest` or `SignHashRequest` requests a new RFC 3161 token from `WithTSAURL` (default `http://tsp.pki.gov.kz:80`). The response must match a fresh random nonce and the SHA-256 imprint of the signature; its TSA signature, purpose, chain and revocation are verified before inclusion. `GetTimeFromSig` authenticates the first signer's timestamp tokens and their binding to its signature, returning the earliest verified token time. It also works with detached CMS without requiring its payload; it does not verify the document's primary signature. Use `VerifyCMS` to validate the document.

Java CMS verification requires a chain to an explicitly trusted root CA; load intermediates needed to construct that chain. The Java trust store is independent of loaded signing keys: changing a PKCS12 store preserves trust without rereading certificate files. Certificate dates are checked by default. `SkipCertificateTimeCheck` skips dates while retaining chain validation. This deliberately differs from the broader effect observed for the native SDK's `KC_NOCHECKCERTTIME` flag and does not promise identical validation policy. The example uses default date checks; the repository's expired PKCS#12 fixtures require an explicit skip only in historical-fixture tests.

`VerifyCMS` checks OCSP revocation by default for every chain certificate except the trusted root, using `WithOCSPURL` (default `http://ocsp.pki.gov.kz`). It authenticates the response signature, responder authorization, certificate and issuer identifiers, freshness, and status. Revoked, unknown, stale, forged, or unavailable status fails verification. Select CRL with `WithJavaRevocation(CertificateValidationCRL, source)`: `source` can be an HTTP(S) URL, a file, or a directory containing `.crl`, `.der`, or `.pem` files; an empty source uses certificate distribution points. Local bundles need full CRLs for all chain issuers. For each issuer, verification selects the newest applicable full CRL with a valid signature and validity period, using `CRLNumber` when available and publication time otherwise; conflicting numbers or publication times are rejected. Stale CRLs in a bundle do not prevent use of a current authenticated CRL. Local CRLs are loaded at `Open`; open a new client to refresh them. `WithJavaRevocation(CertificateValidationNone, "")` explicitly disables only revocation for offline use and is reported in diagnostics. `SkipCertificateTimeCheck` does not bypass revocation.

When an RFC 3161 `signatureTimeStampToken` is present, verification checks its imprint over the CMS signature bytes, TSA signature, ESSCertID/ESSCertIDv2, TSA certificate purpose, and its chain and validity at the timestamp time. TSA-chain revocation uses current evidence under the selected mode. Load the TSA root and intermediates as well; they can differ from the document signer's chain. An untrusted or invalid timestamp rejects the whole CMS, even with `SkipCertificateTimeCheck`. Timestamp time does not replace the current date for the primary signer's certificate checks. This is not archival revocation validation as of signing time.

Standalone `ValidateCertificate` supports None, CRL, and OCSP modes, including validated OCSP output with `ReturnOCSPResponse`. An explicit `CheckTime` validates certificate dates and the chain at that instant in None/CRL modes, taking precedence over `SkipCertificateTimeCheck`. CRL evidence must cover that instant; revocations dated after it do not invalidate that historical result. Historical OCSP validation requires archived evidence and remains unsupported. Full direct CRLs are supported; delta, indirect, and scoped CRLs are rejected. Delegated OCSP responders require `OCSPSigning` and `id-pkix-ocsp-nocheck`; responders without the latter are explicitly unsupported. Clock skew tolerance is five minutes; OCSP responses without `nextUpdate` are accepted for at most 24 hours from `thisUpdate`. A missing nonce is allowed with a fresh authenticated response; a mismatched nonce is rejected. CMS countersignatures, nested timestamps and hardware tokens remain unsupported. Java-specific unsupported operations match `ErrJavaUnsupported`; methods absent from this backend need not match that sentinel. Provider failures use `JavaError`, which has no native KalkanCrypt status code.

TSA and revocation network requests run in Go: `EndpointPolicy` also applies to certificate-derived URLs, redirects are disabled, and each HTTP request has a 15-second timeout. Decoded responses are limited to 64 MiB or a smaller positive `WithMaxInputSize`. `WithProxy` configures an HTTP proxy with optional Basic authentication for these requests, including HTTPS CONNECT. HTTP proxy environment variables are not used. Destinations have no host allowlist by default; configure `WithEndpointPolicy` when processing untrusted certificates.

`SignXML`, `VerifyXML`, `SignWSSE`, `GetCertFromXML` and `GetSigAlgFromXML` additionally require the Kalkan XMLDSig adapter, Apache Santuario and SLF4J API. Pass their absolute paths alongside `WithJavaProvider`:

```go
kalkan.WithJavaXMLLibraries(
    "/opt/kalkan/java/kalkancrypt-xmldsig-0.5.jar",
    "/opt/kalkan/java/xmlsec-3.0.6.jar",
    "/opt/kalkan/java/slf4j-api-2.0.9.jar",
)
```

The adapter supports RSA/SHA-256, GOST95 and GOST2015-512 XML signing; GOST2015-256 XML signing is unavailable in XMLDSig adapter 0.5. All six public canonicalization modes are supported. WS-Security signs the selected SOAP 1.1/1.2 Body with an exclusive-canonicalization reference and embeds its X509v3 certificate in a `wsse:KeyIdentifier`, matching the native SDK. Verification and certificate extraction also accept local BinarySecurityToken references. `VerifyXML` verifies all signatures and applies the same explicit trust and OCSP/CRL policy; SOAP verification also requires the correct `ExpectedBodyID`.

XML IDs must be globally unique and contain only XML `NameChar` characters excluding colon; numeric IDs are accepted for native compatibility. URI escapes in references are unsupported. References are limited to the same document or a unique element ID, with enveloped-signature and canonicalization transforms; XPointer, external references, XPath/XSLT transforms, `ds:Object`, XAdES and XML timestamp objects are rejected. Adding a signature with `SignXML` returns `ErrJavaUnsupported` if the result would invalidate an existing signature. This preservation check verifies signatures and referenced content without checking existing signers' trust or certificate dates. Certificate/algorithm extraction returns metadata and does not substitute for signature verification. The hash, CMS and certificate APIs remain available when these optional XML JARs are omitted.

Each Java client owns a persistent child process and exchanges requests through pipes. Calls within one client are serialized; synchronize a complete load-and-sign sequence if sharing it across keys. Cancellation before a queued call starts leaves the session usable. Cancellation after a worker request starts terminates the Java session; subsequent calls return `ErrJavaWorkerFailed`, and recovery requires a new `Open`. `Close` reaps the process and removes the temporary worker sources and classes. Inputs and outputs are buffered in full; this is not a streaming API. `Hash`, `SignCMS`, `VerifyCMS` and trusted-certificate file inputs must be regular files and also honor `WithMaxInputSize`; PKCS12 containers are loaded separately by the provider. CMS, ZIP and CRL file reads share cancellation and size checks; individual Java protocol fields cannot exceed the signed 32-bit array limit. Go checks cancellation between file reads but cannot interrupt an operating-system filesystem call. `WithMaxOutputBufferSize` bounds returned fields. These limits do not bound total JVM memory.

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

For the native backend, `Open` configures these production endpoints by default:

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

## Native runtime model

KalkanCrypt state is process-global. Native calls are serialized individually. A `LoadKeyStore` call followed by signing is not atomic: other calls can run between them. Callers sharing a client across different key stores must synchronize the entire load-and-sign sequence or use separate processes.

Keep and share the client pointers returned by `Open` or `ckalkan.New`; do not copy client structs. `go vet` detects accidental copies, including copies of the low-level `ckalkan.Client`.

After a successful native `LoadKeyStore`, the client restores every certificate successfully loaded through `WithTrustedCertificate` or `LoadTrustedCertificate` before allowing another operation to run. Certificate bytes are copied after their initial load and retained until `Close`; certificate files must remain available and unchanged for subsequent key-store loads. Restoration finishes even if the context is canceled after the native key-store load starts. A restoration error reports partial success: the key store has changed, trust may be incomplete, and a later `LoadKeyStore` retries restoration. The key-store change is not rolled back.

`context.Context` can cancel waiting for the root client's call gate. It cannot interrupt the low-level process mutex wait, library loading, or an active KalkanCrypt call, including `Init`. Cleanup after failed or canceled `Open` also waits without a context.

`Client.Close()` waits for the active call and can block indefinitely. `Client.CloseContext(ctx)` stops the caller’s wait on `ctx.Err()`, leaves the client in closing state, and rejects new operations. Enforce hard native-call deadlines with process isolation. Closing starts even if the context is already canceled. Once closing finishes, repeated calls return the saved result.

On Windows, `LoadLibraryExW` uses `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`. The current working directory and `PATH` are excluded. Narrow `char*` arguments are encoded as UTF-8 with a terminating NUL.

## Optional process isolation

Import `github.com/skarm/kalkan/isolated` to run each native client in a dedicated child process. The application provides its own worker mode in the same executable; no separate worker command or build is needed. `kalkan.Open` with `WithLibraryPath` keeps its in-process behavior.

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

For the native backend, `WithMaxInputSize` caps high-level in-memory inputs and files read by `GetCertFromCMS`. It does not apply to files read directly by the native SDK or native output buffers. The Java backend also enforces it on payload and trusted-certificate files read by its Go adapter; it does not bound PKCS12 containers. Native output buffers have a 64 MiB hard limit by default (`kalkan.DefaultMaxOutputBufferSize`). `WithMaxOutputBufferSize(0)` restores that default; a positive value selects a smaller or larger limit (up to the native C `int` maximum), and a negative value makes `Open` return `ErrInvalidInput`. The option is forwarded to `ckalkan.WithMaxBufferSize`. Exceeding the active limit returns `ckalkan.OutputBufferLimitError` before an oversized retry or allocation.

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

`GetCertFromXML` returns one embedded certificate per signature in document order. When Java encounters multiple embedded certificates, it identifies the signer by verifying `SignatureValue` over `SignedInfo` with each candidate; missing or ambiguous matches fail. Extraction does not verify referenced document content, certificate dates or trust. The native backend does not verify signatures during extraction. To avoid the native SDK's ambiguous lookup by position or `Signature Id`, extraction uses a copy with unqualified `ds:Signature` `Id` attributes removed. The caller's XML is unchanged, and this copy is never used by `VerifyXML`.

Additional direct references may cover other WS-Security nodes. SOAP input must be UTF-8; one optional BOM at the start is accepted without changing the bytes passed to native verification. Non-SOAP XML accepts UTF-8 or an ASCII-compatible declared encoding when the prolog and root tag are ASCII.

For the native backend, the wrapper does not independently allowlist `CanonicalizationMethod`, `DigestMethod`, or `SignatureMethod`: the supported cryptographic algorithms depend on the installed KalkanCrypt version and repository fixtures do not establish a stable complete set. KalkanCrypt remains responsible for rejecting unsupported methods.

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

The Java backend implements `SignZIP`, `VerifyZIP` and `ExtractZIPSignerCertificate` using the NCA `META-INF/NCAManifest.xml` format and a detached CMS signature. It signs a regular file, a directory tree, a pipe-separated native SDK file list, or an unsigned ZIP. Signing an existing signed ZIP first verifies it, then adds a CMS signer. Verification checks all payload digests, all CMS signatures, explicit trust, revocation and any present timestamps. Native Linux KalkanCrypt 2.0.13 and Java containers were verified in both directions.

Java ZIP processing buffers the archive and payloads in memory, capped at 64 MiB (or a smaller positive `WithMaxInputSize`) and 4096 archive entries including metadata. Traversal paths, duplicate/case-alias names, symlinks and unsigned extra files are rejected. Local headers must agree with the central directory; unlisted local entries and prepended data or executables are rejected. New archives use SHA-256 payload digests; verification also supports the native GOST95 and GOST2015-512 digest URIs. Empty containers, alternate manifest formats and multiple independent CMS references are unsupported. Java output creation uses exclusive creation; `WithAtomicZIPOutput()` also delays publication until the archive is complete. Certificate extraction uses one-based `SignerID` values: 1 selects the first signer.

`SignZIPRequest.OutputPath` must end with `.zip`, case-insensitively. Existing requested and normalized output paths are rejected before the native call. The native KalkanCrypt backend creates the file without an atomic create-if-absent guarantee.

`WithAtomicZIPOutput()` enables atomic publication of completed ZIP output without replacing an existing file. KalkanCrypt writes into a private temporary directory next to the output; temporary files are removed when the operation returns. This option requires hard-link support and an output directory controlled by the application. It is disabled by default.

ZIP input paths are forwarded after empty-path and NUL validation. Keep the files unchanged until each operation returns.

`VerifyZIP` and `ExtractZIPSignerCertificate` are independent. Certificate extraction does not verify the ZIP signature. Call `VerifyZIP` first when both results are required.

## Diagnostics

`WithObserver(func(ctx context.Context, event kalkan.OperationObservation) { ... })` reports backend-call attempts, including setup during `Open` and final `Close`. `QueueWait`, `NativeDuration`, and `TotalDuration` measure the call helper; validation before it and diagnostic callbacks are excluded. `NativeDuration` includes checks and lock waits inside the backend callback. `ErrorClass`, `NativeCode`, and `Expected` describe the outcome without raw error text or input/output data. Returned errors are unchanged. Certificate enumeration endings and absent optional properties retain their expected status.

Observers run synchronously after the client call gate is released, may run concurrently, and must not panic. A slow observer delays its caller; `Close` publishes its saved result before invoking diagnostics and may return first. `WithLogger` records the same safe metadata and never records raw SDK error messages, paths, URLs, or payloads. Timings are not collected when both logger and observer are absent.

## Checks

```sh
make check
```

Java integration tests, including on macOS:

```sh
kalkan_java_sdk="$PWD/../kcsdk/java"
KALKANCRYPT_JAVA_PROVIDER="$kalkan_java_sdk/knca_provider_jce_kalkan-0.7.5.jar" \
KALKANCRYPT_JAVA_XML_LIBRARIES="$kalkan_java_sdk/kalkancrypt-xmldsig-0.5.jar:$kalkan_java_sdk/xmlsec-3.0.6.jar:$kalkan_java_sdk/slf4j-api-2.0.9.jar" \
KALKANCRYPT_JAVA_EXECUTABLE=java \
go test -count=1 ./...
```

`KALKANCRYPT_JAVA_XML_LIBRARIES` enables the XML/WS-Security tests; omit it for provider-only tests. Its path-list separator is `:` on macOS/Linux and `;` on Windows. CI reads all four JARs from the private `skarm/kcsdk` repository and runs on macOS/Linux with JDK 17 and 26. See [test setup](.github/TESTING.md#running-checks) for the required checkout token and fork behavior.

The Java suite checks timestamp issuance/extraction, adding CMS signers, XML/WS-Security, ZIP containers, certificate properties, HTTP proxies, historical certificate/CRL validation, native-reference hash vectors, attached/detached CMS in DER/Base64/PEM, file and empty inputs, tamper rejection, precomputed-digest signing, PKCS#12 password failures, certificate dates and trust, signer-certificate extraction, and existing native CMS fixtures. It was run with provider 0.7.5 and JDK 17 and 26 on macOS ARM64. Live bidirectional native/Java tests additionally require `KALKANCRYPT_LIBRARY` on a supported native platform. Tests that require an unset backend environment variable are skipped.

Revocation and timestamp tests use independently generated ephemeral RSA certificates, CMS, CRLs, OCSP responses, and local HTTP servers. They cover revoked intermediates and TSAs, unknown status, wrong issuers/nonces/signatures/imprints, untrusted TSAs, stale evidence, unavailable services, URL restrictions, and network cancellation. Historical CMS fixtures contain production TSA timestamps and must fail without the corresponding trust. To additionally verify those original files completely, set `KALKANCRYPT_JAVA_TSA_CERTIFICATES` to a directory containing public `root_gost_2022.cer` and `nca_gost_2022.cer` from the [NCA website](https://pki.gov.kz/en/cert-en/). Production certificates are not checked into the repository. Primary signatures are also tested separately on a copy with the unsigned timestamp attribute removed.

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
