# kalkan

Go API for applications that use the native KalkanCrypt SDK and the national
cryptographic standards of the Republic of Kazakhstan.

## Packages

Application code should normally use the root package:

```go
import "github.com/skarm/kalkan"
```

It exposes typed operations for CMS, XML, WS-Security, hashing, ZIP containers,
certificate loading, certificate validation, OCSP, TSA, and proxy settings.

`github.com/skarm/kalkan/ckalkan` is the low-level binding. Use it only when the
root package does not expose the native operation you need. Direct `ckalkan`
callers are responsible for native flags, encodings, buffer sizes, ABI limits,
and process isolation.

## Supported platforms

The KalkanCrypt SDK and native libraries are not stored in this repository. Pass
the SDK library path explicitly with `kalkan.WithLibraryPath`.

Supported targets:

- `linux/amd64` with `CGO_ENABLED=1`
- `windows/amd64`

Unsupported targets:

- Windows x86 / `GOARCH=386`
- Linux with `CGO_ENABLED=0`
- Other operating systems

The KalkanCrypt library path must be absolute. Dependent SDK libraries must live
in a trusted, read-only deployment directory controlled by the service operator.
Do not rely on writable working directories or user-controlled DLL/shared-object
search paths.

On Windows, use the x64 KalkanCrypt DLL. The Windows driver passes narrow
`char*` strings as UTF-8 bytes plus a terminating NUL; run the real-DLL smoke
tests against the exact DLL you deploy if paths, aliases, or passwords contain
non-ASCII characters.

## Install

```sh
go get github.com/skarm/kalkan
```

## Open a client

`Open` initializes KalkanCrypt inside the current process. All native calls share
KalkanCrypt process-global state.

```go
ctx := context.Background()

client, err := kalkan.Open(ctx,
	kalkan.WithLibraryPath("/opt/kalkan/libkalkancryptwr-64.so"),
	kalkan.WithEnvironment(kalkan.TestEnvironment),
)
if err != nil {
	return err
}
defer client.Close()

err = client.LoadKeyStore(ctx, kalkan.KeyStore{
	Type:     kalkan.PKCS12,
	Path:     "/secure/keys/signing.p12",
	Password: os.Getenv("KALKAN_KEY_PASSWORD"),
})
if err != nil {
	return err
}
```

## Runtime model

`context.Context` can cancel waiting to enter a native call, including waiting
for the in-process serialization lock. It cannot interrupt a KalkanCrypt call
that has already entered the shared library. Do not treat an in-process context
deadline as a hard native-call timeout.

`Client.Close()` is the blocking close variant. It can wait forever if another
goroutine is stuck inside a native KalkanCrypt call. For service shutdown paths,
use `Client.CloseContext(ctx)`: it returns `ctx.Err()` when the caller stops
waiting, while the client remains in closing state and rejects new operations.

Backend services that need failure containment or hard native-call time limits
should isolate KalkanCrypt outside this package, for example behind a separate
service, worker process, or process pool that the application can terminate and
replace. That isolation boundary is deployment/application architecture, not a
goroutine-level feature of this wrapper.

## Sources and limits

Operations accept `Source` values:

- `kalkan.Bytes`: raw in-memory data
- `kalkan.Base64`: base64 text
- `kalkan.PEM`: PEM text
- `kalkan.DER`: DER binary data
- `kalkan.File`: a path passed to KalkanCrypt

`File` preserves the path string. Empty paths and embedded NUL bytes are rejected
before native calls; other path errors are left to KalkanCrypt. Use file sources
only for trusted service-controlled paths. For untrusted uploads, prefer
in-memory sources with `WithMaxInputSize` or copy the data into a private
service-controlled temporary directory.

In-memory source constructors store the caller-provided byte slice directly.
Treat those slices as immutable until the operation returns.

`WithMaxInputSize` caps high-level in-memory inputs before native calls. It does
not apply to file sources or native output buffers.

`WithMaxOutputBufferSize` sets the high-level cap for native output buffer retry
logic and is forwarded to `ckalkan.WithMaxBufferSize`.

## CMS and hash signing

CMS signing returns raw DER by default. Use `CMSOutputBase64` or `CMSOutputPEM`
when text output is required.

`SignHashRequest.Digest` is an already calculated digest, not the original
payload. Set `SignHashRequest.DigestAlgorithm` to the algorithm that produced
the digest. The zero value is `SHA256`; GOST R 34.11-2015 512-bit digests must
use `GOST2015_512`.

```go
digest, err := client.Hash(ctx, kalkan.HashRequest{
	Algorithm: kalkan.GOST2015_512,
	Data:      kalkan.Bytes(payload),
})
if err != nil {
	return err
}

cms, err := client.SignHash(ctx, kalkan.SignHashRequest{
	Digest:          digest.Data,
	DigestAlgorithm: digest.Algorithm,
	OutputFormat:    kalkan.CMSOutputDER,
})
```

## XML and WS-Security

`VerifyXML` checks the native XML signature result. If the application reads
business data from a SOAP Body after verification, set
`VerifyXMLRequest.ExpectedBodyID` to the expected `wsu:Id`.

With `ExpectedBodyID` set, the wrapper requires:

- exactly one SOAP 1.1 or SOAP 1.2 Body
- that Body to carry the expected `wsu:Id`
- no duplicate element with the same `wsu:Id`
- an XMLDSig reference to `#ExpectedBodyID`

This prevents accepting a valid signature over one node while the application
reads business data from another node.

## Certificate validation

`ValidateCertificateRequest.Mode` must be explicit:

- `CertificateValidationOCSP`
- `CertificateValidationCRL`
- `CertificateValidationNone`

Use `CertificateValidationNone` only as an intentional opt-out from external
revocation checking.

DER, PEM, and base64 certificate sources are supported. PEM input must contain
exactly one `CERTIFICATE` block. CRL `RevocationSource` paths are checked for
embedded NUL bytes and then passed directly to KalkanCrypt.

The built-in production and test OCSP/TSA defaults use HTTP endpoints from the
KalkanCrypt ecosystem. Override them with `WithOCSPURL` and `WithTSAURL`, or
route traffic through a protected proxy under your operational control.

For certificate metadata hot paths, prefer `X509CertificateGetInfoFields` over
`X509CertificateGetInfo` so only required native properties are fetched.
`CertificateInfo` includes Kazakhstan-oriented `IIN`, `BIN`, subject type, and
recognized NCA roles when the relevant subject and policy fields are requested.

## ZIP containers

`SignZIPRequest.OutputPath` must end with `.zip`, case-insensitively. KalkanCrypt
creates the output file inside the native library. The wrapper rejects existing
requested/normalized output paths before the native call and checks the created
file after the call, but it cannot make native file creation atomic.

Use a private service-controlled output directory:

```go
outputDir, err := os.MkdirTemp("", "kalkan-signzip-*")
if err != nil {
	return err
}
defer os.RemoveAll(outputDir)

if err := os.Chmod(outputDir, 0o700); err != nil {
	return err
}

signed, err := client.SignZIP(ctx, kalkan.SignZIPRequest{
	InputPath:  inputPath,
	OutputPath: filepath.Join(outputDir, "signed.zip"),
})
```

`SignZIP.InputPath`, `VerifyZIP.Path`, and `ZIPSignerCertificate.Path` are passed
directly to KalkanCrypt after empty-path/NUL validation.

## Secrets

`KeyStore.Password` and `Proxy.Password` are strings. Go strings, native SDK
state, and SDK-internal copies cannot be zeroized by this package.

## Tests

Run unit tests:

```sh
make test
```

Run vet and race tests:

```sh
make vet
make test-race
```

Run the full local check:

```sh
make check
```

GitHub CI separates public checks from native SDK checks. Public checks run
`go test ./...`, `go vet ./...`, `go test -race ./...`, golangci-lint,
`govulncheck -show verbose ./...`, and Windows pure-Go tests. The Linux native
SDK job requires the `KCSDK_TOKEN` secret for same-repository runs; fork pull
requests may skip it because secrets are unavailable.

Run real-native tests when the SDK is installed:

```sh
KALKANCRYPT_LIBRARY=/path/to/libkalkancryptwr-64.so \
KALKANCRYPT_SDK_ASSETS=/path/to/testdata \
LD_LIBRARY_PATH=/path/to/sdk/libs \
make test-native
```

Run the Linux Docker test build:

```sh
make docker-test
```

Run Windows tests on `windows/amd64` with the x64 DLL:

```powershell
$env:KALKANCRYPT_LIBRARY = "C:\KalkanCrypt\KalkanCrypt.dll"
go test ./...
```
