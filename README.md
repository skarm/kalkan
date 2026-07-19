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

Use `ckalkan` when the root package does not expose the required operation. Use it to build a custom high-level layer over KalkanCrypt with its own request types, validation, buffer policies, logging, or error mapping.

`ckalkan` closely mirrors the native API. Calling code owns native flags, encodings, buffer sizing, and status-code handling; it must also account for client lifecycle, ABI constraints, and any required process isolation.

### Low-level output buffers

The `ckalkan` buffer options cover two ABI shapes:

- `WithListBufferSize` sets the initial allocation for `KC_GetTokens` and `KC_GetCertificatesList`; the default is 1 MiB. In the tested Linux SDK 2.0.13, these functions receive no byte-capacity argument, and `tk_count` and `cert_count` are output item counts. The option controls allocation size but does not bound the native write.
- `WithBufferSize` sets the global initial capacity for length-aware output calls when a request does not specify its own capacity. Without this option, operation-specific defaults are 128 bytes for hashes, 4 KiB for metadata, 8 KiB for certificates, and 64 KiB for signatures and generic outputs. Attached CMS uses the in-memory input or file size plus a conservative signature reserve; CMS Base64 and PEM expansion is included. Signed XML/WSSE uses the in-memory XML size plus the same reserve (`KC_IN_FILE` is not supported by these two SDK calls). These calls initialize an output-length parameter with the capacity and retry after `KCR_BUFFER_TOO_SMALL`.
- `WithMaxBufferSize` sets an opt-in hard allocation limit. Without it, 64 MiB is only a soft growth checkpoint: estimated or native-reported results may grow beyond it up to the native `int` ABI limit. For the two list calls, a hard limit below their configured initial allocation rejects the call instead of silently shrinking an unbounded native buffer; the SDK still receives no byte-capacity bound.

On Linux, `ZipConVerify` requires a 64 KiB safety allocation because SDK 2.0.13 can write past a smaller reported capacity. If an explicit hard limit is below that safety minimum, the call fails before entering the native library.

Positive `WithBufferSize` and `WithListBufferSize` values are normalized to at least 64 KiB. `WithMaxBufferSize` is honored exactly.

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

## Runtime model

KalkanCrypt state is process-global. Native calls are serialized. `context.Context` cancels lock acquisition but cannot interrupt a call after control enters KalkanCrypt.

`Client.Close()` waits for the active call and can block indefinitely. `Client.CloseContext(ctx)` stops the caller’s wait on `ctx.Err()`, leaves the client in closing state, and rejects new operations. Enforce hard native-call deadlines with process isolation.

On Windows, `LoadLibraryExW` uses `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`. The current working directory and `PATH` are excluded. Narrow `char*` arguments are encoded as UTF-8 with a terminating NUL.

## Inputs and bounds

Operations use `Source` values:

- `kalkan.Bytes(data)`: raw in-memory bytes for payloads, XML, or already-decoded binary data; the operation selects the field-specific native flags
- `kalkan.Base64(data)`: in-memory input that already contains Base64 text; the constructor does not encode `data`
- `kalkan.PEM(data)`: an existing PEM representation; the constructor does not create the PEM envelope
- `kalkan.DER(data)`: an existing DER representation, used to select DER explicitly for CMS and certificate inputs
- `kalkan.File(path)`: a path forwarded to KalkanCrypt by operations that support `KC_IN_FILE`

Supported variants are operation-specific.

The in-memory constructors neither copy nor transform the provided byte slice. Operation-specific validation may decode PEM or Base64 before the native call. `File` forwards the original path after empty-path and NUL validation. Keep borrowed slices and referenced files unchanged until the call returns.

`WithMaxInputSize` caps high-level in-memory inputs. It does not apply to file sources or native output buffers. `WithMaxOutputBufferSize` enables a hard output-allocation limit and is forwarded to `ckalkan.WithMaxBufferSize`; without it, output growth has no user-configured hard cap.

Native binary outputs are returned strictly according to the SDK-reported `outLen`; zero bytes inside that range are preserved. The returned slice has `len` and `cap` limited to the logical result, so unused buffer capacity is not exposed. Byte-slice results are bounded views rather than copies: keeping a result alive also retains the successful native backing allocation, avoiding a second large allocation and copy. Known textual outputs use C-string semantics and end at the first NUL because some KalkanCrypt methods report a fixed-size block and leave unspecified bytes after the terminator.

`KeyStore.Password` and `Proxy.Password` are strings. Go memory, KalkanCrypt state, and SDK-internal copies cannot be zeroized by this package.

## CMS and digest signing

CMS output is raw DER by default. Select `CMSOutputBase64` or `CMSOutputPEM` for text output.

`SignHashRequest.Digest` is the precomputed digest. `DigestAlgorithm` must match the digest algorithm; its zero value is `SHA256`. Use `GOST2015_512` for GOST R 34.11-2015 512-bit digests.

## XML and WS-Security

`VerifyXML` delegates cryptographic verification to KalkanCrypt. For SOAP 1.1 and SOAP 1.2, `ExpectedBodyID` is required and the wrapper enforces:

- exactly one `ds:Signature`
- exactly one direct-child `ds:SignedInfo`
- exactly one SOAP Body that is a direct child of the Envelope and has the expected `wsu:Id`
- a direct `ds:Reference` to `#ExpectedBodyID`
- the Body reference has either no `ds:Transforms`, or exactly one direct `ds:Transform` using Exclusive XML Canonicalization (`http://www.w3.org/2001/10/xml-exc-c14n#`)
- no duplicate matching `wsu:Id`, `xml:id`, `Id`, or `ID`

XML operations accept `kalkan.Bytes`; file and pre-encoded sources are rejected.

Additional direct references may cover other WS-Security nodes. SOAP input must be UTF-8. Non-SOAP XML accepts UTF-8 or an ASCII-compatible declared encoding when the prolog and root tag are ASCII.

The wrapper does not independently allowlist `CanonicalizationMethod`, `DigestMethod`, or `SignatureMethod`: the supported cryptographic algorithms depend on the installed KalkanCrypt version and repository fixtures do not establish a stable complete set. KalkanCrypt remains responsible for rejecting unsupported methods.

## Certificate validation

`ValidateCertificateRequest.Mode` must be one of `CertificateValidationOCSP`, `CertificateValidationCRL`, or `CertificateValidationNone`. The zero value is invalid. `CertificateValidationNone` explicitly disables external revocation checks.

Certificate input supports DER, PEM, and base64; `kalkan.File` is rejected. PEM input must contain exactly one `CERTIFICATE` block. `RevocationSource` is a CRL path in CRL mode and an OCSP URL override in OCSP mode.

`WithOCSPURL` and `WithTSAURL` override the package defaults. URL validation checks syntax but does not restrict the destination.

Use `X509CertificateGetInfoFields` on metadata hot paths. `CertificateInfo` exposes IIN, BIN, subject type, and recognized NCA roles when the corresponding fields are requested.

## ZIP containers

`SignZIPRequest.OutputPath` must end with `.zip`, case-insensitively. Existing requested and normalized output paths are rejected before the native call. KalkanCrypt creates the file without an atomic create-if-absent guarantee.

ZIP input paths are forwarded after empty-path and NUL validation. Keep the files unchanged until each operation returns.

`VerifyZIP` and `ExtractZIPSignerCertificate` are independent. Certificate extraction does not verify the ZIP signature. Call `VerifyZIP` first when both results are required.

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

## Project policies

- [Contributing](.github/CONTRIBUTING.md)
- [Security policy](.github/SECURITY.md)
- [Code of Conduct](.github/CODE_OF_CONDUCT.md)
- [MIT License](LICENSE.md)

The repository license does not grant rights to KalkanCrypt SDK binaries.
