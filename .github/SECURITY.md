# Security Policy

## Supported versions

kalkan tracks active development on `master`. Security fixes land there first.
If a tagged release line is still current, a low-risk fix may be backported, but
older checkouts should update before reporting unless the issue reproduces on
`master`.

| Version | Supported |
|---|---|
| latest `master` | yes |
| latest tagged release | best effort |
| older tags or checkouts | no, update first |

Unsupported targets listed in the README are not security-supported targets.

## Reporting a vulnerability

**Report privately. Do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/skarm/kalkan/security) of the
   repo.
2. Click **Report a vulnerability** to open a private GitHub Security Advisory.
3. Include a clear description, reproduction steps, and the impact you observed.

That keeps details out of public view until a fix or mitigation is available.
Please give a reasonable window to patch before public disclosure.

Include as much of the following information as you can safely share:

- Affected package, function, or native boundary.
- Go version, operating system, architecture, and KalkanCrypt SDK version.
- Whether the issue requires the real native SDK, a specific certificate, a ZIP
  container, XML or CMS input, OCSP/TSA traffic, or proxy configuration.
- A minimal reproducer or test case that does not contain production secrets.
- Impact assessment, including confidentiality, integrity, availability, and
  whether attacker-controlled input is required.

## Secrets and native SDK assets

kalkan never needs repository-stored production secrets. Keep all sensitive
material outside issues, pull requests, commits, test fixtures, and advisories
unless it is synthetic and safe to publish.

- Do not paste private keys, production certificates, key-store passwords, proxy
  passwords, tokens, or proprietary SDK binaries.
- Redact paths and aliases if they expose customer, tenant, or deployment
  details.
- If a real credential was committed anywhere, treat it as compromised: rotate
  it immediately, then report privately so maintainers can coordinate cleanup.
- The `KCSDK_TOKEN` CI secret is only for same-repository native SDK checks.
  Fork pull requests should not need it.

## Scope

This project wraps native KalkanCrypt calls for CMS, XML, WS-Security, hashing,
ZIP containers, certificate loading and validation, OCSP, TSA, and proxy
settings. The main issues worth a private report:

- A path that causes unsafe native library loading or unsafe DLL/shared-object
  search behavior.
- Missing validation before passing attacker-controlled data, paths, encodings,
  or sizes to KalkanCrypt.
- XML signature wrapping, WS-Security, CMS, ZIP, or certificate validation
  behavior that can cause an incorrect security decision.
- OCSP, TSA, or proxy handling that can redirect trust decisions or leak
  sensitive operational data.
- Unbounded memory use, output buffer growth, lifecycle handling, or native-call
  waiting behavior that can cause denial of service in this wrapper.
- Accidental exposure of secrets through errors, logs, test fixtures, or
  documentation.

Usually out of scope:

- Vulnerabilities only in the proprietary KalkanCrypt SDK or deployment
  environment, unless this wrapper makes them materially worse.
- Reports that require unsupported operating systems, unsupported
  architectures, or `CGO_ENABLED=0`.
- Issues caused by using untrusted DLL/shared-object search paths, writable SDK
  directories, or production secrets against documented guidance.

## Disclosure

Maintainers will coordinate remediation through the private advisory when
possible. Public disclosure should wait until a fix or mitigation is available,
or until maintainers and the reporter agree on a disclosure date.

Non-sensitive hardening ideas may be opened as public issues.
