# OCSP interoperability fixtures

Generated using golang.org/x/crypto/ocsp v0.57.0 and standard-library ECDSA P-256.
`request.der` queries `leaf.der` under `issuer.der`; `good.der` is signed by that
issuer. These certificates contain no real identities or production keys.
Validity: 2020-01-01 through 2050-01-01; tests validate at 2030-01-01.
The test suite itself requires only the Go standard library.
