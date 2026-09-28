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

These files provide public-key verification on the 512-bit parameter set A
used by Kazakhstan's GOST 2015 certificates and the Streebog-512 hash wrapper.
`gost3410/params.go` retains only `CurveIdtc26gost341012512paramSetA`; its
declaration, parameters and function body are copied unchanged from the
release. Other curve definitions and the Streebog-256 wrapper are omitted,
as are signing, key generation, key agreement and other ciphers.

The shared Streebog primitive and its official test vectors, including
256-bit and 512-bit cases, are retained unchanged. Imports are rewritten to
local package paths; the remaining algorithm implementations and tests are
otherwise unchanged. The subset requires only the Go standard library;
it adds no module dependency.

Copyright Sergey Matveev and the GoGOST contributors. This subset is licensed
under GPL-3.0; see LICENSE.md (upstream COPYING) and the notices in each source
file. It is not covered by the repository's MIT license.
