# Contributing to kalkan

Thanks for helping make kalkan better. This is a Go wrapper around the native
KalkanCrypt SDK, so keep contributions surgical, verifiable, and explicit about
native-boundary behavior.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) in all project spaces.

## Setup

```bash
git clone https://github.com/skarm/kalkan && cd kalkan
go version # Go 1.26+
make test
```

The KalkanCrypt SDK and native libraries are not stored in this repository. Most
unit tests run without the real SDK; native smoke tests need a local SDK install.

## Run the checks

Public checks:

```bash
make fmt
make vet
make test
make test-race
make check
```

`make check` runs formatting, tests, vet, race tests, and `golangci-lint` when
the linter is installed locally. GitHub CI also runs `govulncheck` and Windows
pure-Go tests.

Real native SDK checks:

```bash
KALKANCRYPT_LIBRARY=/path/to/libkalkancryptwr-64.so \
KALKANCRYPT_SDK_ASSETS=/path/to/testdata \
LD_LIBRARY_PATH=/path/to/sdk/libs \
make test-native
```

Linux Docker native check:

```bash
make docker-test
```

Windows check on `windows/amd64` with the x64 KalkanCrypt DLL:

```powershell
$env:KALKANCRYPT_LIBRARY = "C:\KalkanCrypt\KalkanCrypt.dll"
go test ./...
```

Fork pull requests may skip the Linux native SDK job because repository secrets
are unavailable.

## What to change

Application-facing features usually belong in the root `kalkan` package.
`github.com/skarm/kalkan/ckalkan` is the low-level binding; use it when the root
package cannot expose the native operation safely yet.

When touching native-boundary code, be strict about:

- Empty paths and embedded NUL bytes.
- Input size limits and native output buffer caps.
- UTF-8, base64, DER, PEM, and platform-specific string handling.
- KalkanCrypt's process-global state and serialized native calls.
- DLL/shared-object loading from trusted, service-controlled directories only.
- XML signature wrapping, CMS verification, ZIP output paths, OCSP/TSA, and
  proxy behavior.

If public behavior changes, update the README or package documentation in the
same pull request.

## Test fixtures

Keep fixtures synthetic and safe to publish. Do not add production certificates,
private keys, passwords, tokens, or proprietary SDK binaries.

If a test requires the real SDK, make that dependency explicit and keep the test
skippable when `KALKANCRYPT_LIBRARY` is unset.

## Commit conventions

- One logical change per PR.
- Use Conventional Commits for commit subjects:

  ```text
  feat: add certificate metadata field
  fix(xml): reject duplicate body IDs
  docs: clarify native library path requirements
  test(zip): cover existing output path rejection
  ```

- Every commit on `master` should leave the repo buildable and testable.
- Update docs with the behavior they describe.

## Before you open a PR

- [ ] `make fmt` was run.
- [ ] `make test` passes.
- [ ] `make vet` passes.
- [ ] `make test-race` passes when the change touches shared state,
      concurrency, buffers, or native-call lifecycle.
- [ ] Native SDK tests were run, or the PR explains why they are not relevant.
- [ ] No secrets, production certificates, or SDK binaries are staged.
- [ ] README or package docs are updated for public behavior changes.

## Secrets and SDK binaries

Secrets are caller-owned runtime data. They do not belong in this repository.

- Do not paste real key-store passwords, proxy passwords, private keys, tokens,
  or production certificates into issues, advisories, pull requests, examples,
  or tests.
- Do not commit KalkanCrypt SDK binaries or proprietary SDK assets.
- If you accidentally commit a secret, rotate it immediately and rewrite the
  branch before opening a PR.

Found a leaked secret or another security issue? Report it privately through a
[GitHub Security Advisory](https://github.com/skarm/kalkan/security/advisories/new)
instead of a public issue or pull request.

## License

By contributing, you agree your work is licensed under the project's
[MIT License](../LICENSE.md).
