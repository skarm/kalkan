# Test architecture

Tests live beside the package that owns the behavior. The Java backend uses
package `javakalkan` for SDK-independent unit tests and external package
`javakalkan_test` for real SDK tests through the public API. The latter neither
imports the bridge implementation nor accesses private client fields.
Keep these boundaries:

- Root `kalkan`: public request validation, source encoding, policy, lifetime,
  logging, and observations. Fakes verify the request sent to the SDK boundary;
  native integration tests verify cryptographic results with the real SDK.
- `internal/javakalkan`: transport framing, cancellation, file/network behavior,
  and actual JVM/provider behavior through the public `kalkan` API. SDK tests
  follow features: hashing, CMS, certificates, revocation, timestamps,
  XML/WS-Security, ZIP, and runtime behavior. `sdk_helpers_test.go` owns client
  setup; `pki_helpers_test.go` generates independent verification fixtures.
  Regressions join their feature file instead of accumulating `review` or
  `extended` files.
- `internal/testfixture`: SDK asset discovery and independent CMS ASN.1 helpers
  shared by the native and Java test layers. Client setup stays in each suite.
- `ckalkan`: native status conversion, buffer growth, output contracts, and
  serialization of process-wide SDK state. Stub-library tests exercise the ABI
  without requiring the proprietary SDK.
- `ckalkan/internal/kalkancrypt`: platform drivers, pointer and string ownership,
  function-table layout, and native buffer boundaries.
- `isolated`: binary framing, limits, request/result preservation, worker
  dispatch, lifecycle, subprocess behavior, and public SDK
  operations. Workers run locally in the test executable; no separate command
  is built.

A CMS case at more than one boundary is not automatically duplicate coverage.
The root test checks flag selection, the binding checks output/error handling,
and the driver checks ABI memory semantics.

## File and test names

- `<area>_test.go`: SDK-independent behavior for an operation or cohesive policy.
- `<area>_sdk_test.go`: Java backend tests requiring the provider JAR, colocated
  in `internal/javakalkan` and using external package `javakalkan_test`.
- `<area>_integration_test.go`: tests requiring a real KalkanCrypt library.
  Put platform suffixes last: `<area>_integration_linux_test.go`.
- `<area>_fixture_test.go`: checks of committed fixture contents that do not
  require the SDK. For example, CMS ASN.1 structure and certificate identity.
- `<area>_helpers_test.go`: shared fixture setup and assertions; keep mutable
  clients and SDK lifetime local to each test.
- `<area>_bench_test.go`: benchmarks. `wrapper_bench_test.go` uses fake native
  calls and measures wrapper overhead, not cryptographic throughput.
- `<area>_fuzz_test.go`: seeded fuzz targets.

Name tests after the operation and observable behavior. A test that only checks
that an ABI call returns a Go-visible status should explicitly say `Smoke`.
Do not create a new file for each regression when its operation already has a
cohesive test file. Conversely, do not merge unrelated operations just to reduce
the file count. Keep platform build constraints and internal/external test
packages intact when moving declarations.

## Test design

Use literal expected results or an independent oracle. Split unrelated input
dimensions instead of multiplying every option into one matrix with production-
like branching. In CMS tests, encoding precedence and detached/time-check flags
are separate concerns; existing files and real signatures validate path behavior.

Every cryptographic rejection needs a successful control and an expected native
error. A failure to open the SDK or load a fixture does not prove that a tampered
signature was rejected. Do not remove guard-page tests, tampering tests, or
binary-output checks as cosmetic duplication.

Every certificate selected by native fixture setup must load successfully.
Assert rejection of malformed or unsupported certificates in an explicit negative
test; logging a setup error and continuing can hide a broken trust environment.

Check SDK availability before expensive fixture generation. Register cleanup
before operations that can fail. Do not add `t.Parallel` to tests sharing the
process-global SDK. Prefer channels to sleeps for synchronization; reserve
timeouts for bounded failure and for behavior that actually depends on time.

For channel-based concurrency tests with a Go fake, use `testing/synctest`:
`synctest.Wait` establishes that goroutines are blocked before asserting that a
call has not completed. Fake time also permits exact queue/native/total duration
assertions. Create the client, channels, contexts, and goroutines inside the same
bubble, and register cleanup to unblock fake calls after a failed assertion.
Inside a bubble, `time.Sleep` advances virtual time without a wall-clock delay.
Keep it when modeling queue, native-call, or observer durations. Use
`synctest.Wait()` for synchronization alone; it does not advance virtual time
and cannot replace the sleeps that establish expected timing values.
Keep real SDK and subprocess tests outside bubbles; native calls, external I/O,
and waits on `sync.Mutex` are not durably blocking operations for `synctest`.
Use the shared `awaitTestEvent` helper for bounded channel waits.

## Running checks

```sh
go test ./...
go test -run=^$ -bench=. -benchtime=1x ./...
go test -race -shuffle=on -count=1 ./...
go vet ./...
golangci-lint run ./...
```

Native integration tests skip when `KALKANCRYPT_LIBRARY` is unset. The filename convention
is descriptive; it is not an additional build tag. Use `make test-native` with
the library and assets configured, or `make docker-test`, to run the native suite.
See [Contributing](CONTRIBUTING.md#run-the-checks) for the environment settings.

Java `*_sdk_test.go` tests in `internal/javakalkan` run when
`KALKANCRYPT_JAVA_PROVIDER` points to
`knca_provider_jce_kalkan-0.7.5.jar`. Set `KALKANCRYPT_JAVA_EXECUTABLE` to the Java
executable if it is not on `PATH`; a JDK is required because the worker is launched
from embedded Java source. For example, with the private SDK checkout beside this
repository:

```sh
kalkan_java_sdk="$PWD/../kcsdk/java"
KALKANCRYPT_JAVA_PROVIDER="$kalkan_java_sdk/knca_provider_jce_kalkan-0.7.5.jar" \
KALKANCRYPT_JAVA_XML_LIBRARIES="$kalkan_java_sdk/kalkancrypt-xmldsig-0.5.jar:$kalkan_java_sdk/xmlsec-3.0.6.jar:$kalkan_java_sdk/slf4j-api-2.0.9.jar" \
KALKANCRYPT_JAVA_EXECUTABLE="$JAVA_HOME/bin/java" \
go test -count=1 ./internal/javakalkan
```

This package command runs both unit and SDK tests; `-run '^TestJava'` selects
only the SDK tests. The full `go test ./...` command also discovers them. Root
`java_test.go` contains only SDK-independent configuration tests.

`KALKANCRYPT_JAVA_XML_LIBRARIES` enables the XML and WS-Security tests and
supplies the three optional JARs to `WithJavaXMLLibraries`. Use the platform's
path-list separator: `:` on macOS/Linux, `;` on Windows. Without this variable,
XML tests skip while provider-only hash, CMS and certificate tests still run.
The private SDK repository must contain these files under `java/`:

- `knca_provider_jce_kalkan-0.7.5.jar`: Kalkan cryptographic provider.
- `kalkancrypt-xmldsig-0.5.jar`: Kalkan XMLDSig algorithm adapter.
- `xmlsec-3.0.6.jar`: Apache Santuario XML signature implementation.
- `slf4j-api-2.0.9.jar`: Santuario logging API dependency.

The Java CI matrix runs on macOS and Linux with JDK 17 and 26; Linux/JDK 26 also
runs the race detector. These jobs check out `skarm/kcsdk` into `.local/kcsdk`
with Git LFS and run the suite with both provider and XML library variables
configured. Java tests use
committed fixtures and independently generated temporary keys/certificates,
CRLs, CMS and OCSP/TSA responses. Local HTTP responders test timestamp issuance,
verification and revocation without depending on live PKI services. XML tests
cover canonicalization, selected nodes, signed SOAP bodies, certificate metadata,
trust, revocation and rejection of altered or unsafe documents.
Live native/Java interoperability tests additionally require
`KALKANCRYPT_LIBRARY` and are not part of the Java-only matrix.

Both native and Java SDK jobs require the `KCSDK_TOKEN` repository secret with
read access to the private `skarm/kcsdk` repository. SDK checkout credentials are
not persisted, and SDK files are not uploaded as artifacts. Fork pull requests
skip these private SDK jobs because their secrets are unavailable. The `required`
job accepts that skip only for fork pull requests; for other runs all Java matrix
jobs must succeed. SDK changes must be available in the private repository before
the consuming workflow can use them.

The benchmark smoke run checks that every benchmark still accepts its inputs;
it is not a performance measurement. CI also fuzzes the isolated IPC decoder
with `FuzzReadMessage` alongside the public input and output-buffer checks.

## Shared fixtures

`internal/testfixture` provides SDK asset discovery, directory walking, ZIP
extraction, CMS fixture parsing, and isolated ZIP copies. File helpers use
`testing.TB`. `ExtractZIP` owns its temporary directory and takes an explicit
`RejectDuplicates` or `OverwriteDuplicates` policy. Shared CMS structure checks
use an independent ASN.1 model.

Each suite owns its certificate selection, missing-fixture behavior, client
setup, and operation assertions. The native driver's directory scan accepts
directories only and applies its own certificate and metadata filters.
