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

`WithListBufferSize` sets the allocation for `KC_GetTokens` and
`KC_GetCertificatesList`, but the SDK functions do not receive its capacity and
cannot enforce that bound.

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

`WithLibraryPath` requires an absolute KalkanCrypt library path.

On Windows, `LoadLibraryExW` searches the target DLL directory and the default
application, user-added, and System32 directories. It excludes the current
working directory and `PATH`.

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

`context.Context` can cancel a wait for the process lock. It cannot interrupt an
active KalkanCrypt call.

`Client.Close()` is the blocking close variant. It can wait forever if another
goroutine is stuck inside a native KalkanCrypt call. For service shutdown paths,
use `Client.CloseContext(ctx)`: it returns `ctx.Err()` when the caller stops
waiting, while the client remains in closing state and rejects new operations.

Hard native-call deadlines require a separate process.

## Sources and limits

Operations accept `Source` values:

- `kalkan.Bytes`: raw in-memory data
- `kalkan.Base64`: base64 text
- `kalkan.PEM`: PEM text
- `kalkan.DER`: DER binary data
- `kalkan.File`: a path passed to KalkanCrypt

`File` passes the original path after empty-path and NUL validation. KalkanCrypt
reports other path errors. Keep the referenced file unchanged until the
operation returns.

In-memory source constructors retain the provided byte slice. Do not mutate it
until the operation returns.

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

`VerifyXML` delegates signature verification to KalkanCrypt. SOAP 1.1 and SOAP
1.2 require `ExpectedBodyID`. Before the native call, the wrapper requires:

- one `ds:Signature`
- one `ds:SignedInfo` that is a direct child of the signature
- one SOAP Body with the expected `wsu:Id`
- one direct reference from `ds:SignedInfo` to `#ExpectedBodyID`
- no duplicate `wsu:Id`, `xml:id`, `Id`, or `ID` with the same value

Additional direct references may cover other WS-Security data. SOAP input must
be UTF-8. Non-SOAP UTF-8 XML is passed to KalkanCrypt unchanged. A declared
ASCII-compatible encoding is also accepted when the prolog and root tag use
ASCII; other encodings are rejected.

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
KalkanCrypt ecosystem. `WithOCSPURL` and `WithTSAURL` replace those defaults.
For one validation request, `RevocationSource` supplies the CRL path or overrides
the OCSP URL. The package validates URL syntax but does not restrict the
destination.

For certificate metadata hot paths, prefer `X509CertificateGetInfoFields` over
`X509CertificateGetInfo` so only required native properties are fetched.
`CertificateInfo` includes Kazakhstan-oriented `IIN`, `BIN`, subject type, and
recognized NCA roles when the relevant subject and policy fields are requested.

## ZIP containers

`SignZIPRequest.OutputPath` must end with `.zip`, case-insensitively. KalkanCrypt
creates the output file inside the native library. The wrapper rejects existing
requested/normalized output paths before the native call and checks the created
file after the call, but it cannot make native file creation atomic.

```go
signed, err := client.SignZIP(ctx, kalkan.SignZIPRequest{
	InputPath:  inputPath,
	OutputPath: outputPath,
})
```

`SignZIPRequest.InputPath`, `VerifyZIPRequest.Path`, and
`ExtractZIPSignerCertificateRequest.Path` are passed unchanged after empty-path
and NUL validation. Keep the referenced files unchanged until each call returns.

`VerifyZIP` and `ExtractZIPSignerCertificate` are independent. Certificate
extraction does not verify the signature. If both results are needed, call
`VerifyZIP` first and keep the file unchanged between calls.

The split API removes `VerifyZIPRequest.SignerID` and
`VerifyZIPRequest.ReturnSignerCertificate`; `VerifyZIP` does not extract a
certificate.

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

Run golangci-lint in the Linux container:

```sh
make docker-lint
```

Run Windows tests on `windows/amd64` with the x64 DLL:

```powershell
$env:KALKANCRYPT_LIBRARY = "C:\KalkanCrypt\KalkanCrypt.dll"
go test ./...
```
