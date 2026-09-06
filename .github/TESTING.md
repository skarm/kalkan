# Test architecture

Tests stay beside the package they exercise. Moving them into a single `tests/`
directory would lose access to package internals or require exporting test hooks.
Keep the existing boundaries:

- Root `kalkan`: public request validation, source encoding, policy, lifetime,
  logging, and observations. Fakes verify the request sent to the SDK boundary;
  integration tests verify cryptographic results with the real SDK.
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
go test -race -shuffle=on -count=1 ./...
go vet ./...
golangci-lint run ./...
```

Integration tests skip when `KALKANCRYPT_LIBRARY` is unset. The filename convention
is descriptive; it is not an additional build tag. Use `make test-native` with
the library and assets configured, or `make docker-test`, to run the native suite.
See [Contributing](CONTRIBUTING.md#run-the-checks) for the environment settings.

## Remaining review items (2026-09-06)

- `internal/testfixture` shares directory walking, ZIP extraction, example names,
  and isolated ZIP copies. File helpers use `testing.TB`; `ExtractZIP` owns its
  temporary directory and takes an explicit `RejectDuplicates` or
  `OverwriteDuplicates` policy. Root and binding tests retain their certificate
  selection, missing-fixture behavior, and duplicate ZIP entry policies. The
  driver's directory scan remains separate because it accepts directories only
  and uses different certificate and metadata filters. Client setup and
  assertions remain local to each layer.
- Large buffer-contract and certificate-property files remain intentionally
  separate by responsibility. Their repeated operation adapters are candidates
  for small local helpers, not a generic test framework shared across all layers.
