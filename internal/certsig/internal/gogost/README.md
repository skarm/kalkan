# GoGOST verification subset

Source: the official [GoGOST 7.0.0 release](http://www.gogost.stargrave.org/Download.html),
published on 2026-03-22. Upstream module path: `go.stargrave.org/gogost/v7`.
The release was the newest listed by the official download page on 2026-09-28.

Archive: <http://www.gogost.stargrave.org/gogost-7.0.0.tar.zst>  
Release metadata: <http://www.gogost.stargrave.org/gogost-7.0.0.tar.zst.meta4>

The archive's SHA-256, SHA-512 and BLAKE2b-512 hashes were checked against
that Metalink metadata. SHA-256:

```text
225aba5cc409546401a7ae37a12d506ee06ce91a4c29b164d8c5d30b7f9ce659
```

The SSH signature from the release metadata was verified with the release's
Ed25519 key, also found in the existing local upstream checkout:
`SHA256:u8X9rPDOhxpyzGs/IugbxXbDeOu/0AttKY+LGAvHBH0`.
The public key and detached signature are retained here. Verification:

```sh
ssh-keygen -Y verify -f PUBKEY-SSH.pub -I gogost@stargrave.org -n file \
    -s gogost-7.0.0.tar.zst.sig < gogost-7.0.0.tar.zst
```

These files provide public-key verification on the 256-bit and 512-bit parameter
sets A corresponding to Kazakhstan's GOST 2015 profiles, with both Streebog hash
wrappers. `gost3410/params.go` retains only
`CurveIdtc26gost341012256paramSetA` and `CurveIdtc26gost341012512paramSetA`;
their declarations, parameters and function bodies are copied unchanged from the
release. The parameters match the Kazakhstan curve definitions in KalkanCrypt
Java 0.7.5 and [RFC 7836, Appendix A](https://www.rfc-editor.org/rfc/rfc7836.html#appendix-A).
Other curve definitions, signing, key generation, key agreement and other ciphers
are omitted.

Local documentation edits align package and API comments with Go conventions.
They also add missing comments for exported declarations. Copyright and license
notices retain their original text.

The shared Streebog primitive and its official test vectors, including
256-bit and 512-bit cases, are retained unchanged. Imports are rewritten to
local package paths. A local correction in `gost3410/public.go` handles equal
points by doubling and rejects a sum at infinity during signature verification;
`../../certsig_test.go` covers both cases. Local corrections to the Streebog
state decoder in `internal/gost34112012/marshal.go` reject invalid digest sizes
and buffered block lengths and copy retained input as required by
`encoding.BinaryUnmarshaler`; `internal/gost34112012/hash_test.go` covers these
contracts. A local correction in `gost3410/curve.go` makes `Curve.Equal` handle omitted optional
parameters without a nil dereference; `../../certsig_test.go` covers comparisons
with and without these parameters. `NewCurve` copies all parameter integers,
including P/Q/A/B/X/Y, optional E/D and the cofactor. Retained constructor inputs
and mutable factory results cannot alter another curve or shared integer constants.
`../../certsig_test.go` covers independence from both other instances and constructor inputs.
`Curve.add` and `Curve.Exp` explicitly handle the point at infinity, including
intermediate sums and doubling a point with Y=0. `Curve.IsInSubgroup` validates
canonical coordinates and checks Q*P=infinity on the cofactor-4 256-bit curve;
the cofactor-1 512-bit curve needs only the coordinate and curve checks.
`../../certsig_test.go` covers torsion and mixed-order points, scalar multiplication
through infinity, and signatures independently produced by KalkanCrypt. Public
SDK fixtures are shared with the certificate and OCSP tests under
`../../../../testdata/ocsp/gost2015_256/` (relative to this directory).
Additional SDK 512-bit and mixed 256/512 certificate and OCSP fixtures are embedded
in the existing root `ocsp_test.go`, including successful verification and rejection
of changed signatures, profile identifiers and issuer keys.
Concurrent verification may share immutable curves, public keys, certificates and
input slices. Arithmetic results, reversed inputs and hash states are local to
each verification; the static Streebog tables are read-only. The existing tests
exercise both profiles together with shared inputs, including parallel OCSP
responses, and check that verification leaves those inputs unchanged. Mutating a
shared object's exported fields during verification is not supported.
The remaining algorithm implementations and existing upstream test cases are unchanged.
The subset requires only the Go standard library; it adds no module dependency.

Copyright Sergey Matveev and the GoGOST contributors. This subset is licensed
under GPL-3.0; see LICENSE.md (upstream COPYING) and the notices in each source
file. It is not covered by the repository's MIT license.
