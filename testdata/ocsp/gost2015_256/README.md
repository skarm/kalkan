# Independent KalkanCrypt GOST-2015/256 fixtures

Generated on 2026-10-17 with the official KalkanCrypt Java provider
`knca_provider_jce_kalkan-0.7.5.jar` from the NCA RK SDK. Its SHA-256 is
`b25f8dd5650f2521235b6d0cd5a66d1e02aeb75820c3bab10cf99452522055ac`.
The SDK generated the keys, certificates and OCSP responses and verified every
certificate and response signature before exporting them. It also produced and
verified the standalone message signature. The generator used no project Go
cryptography.

These are synthetic identities and public test keys. JDK SHA1PRNG was seeded
separately per fixture for deterministic keys and signature nonces. A second
generation was byte-for-byte identical. No private keys are committed.

- `gost256-ca.der`: self-signed CA, serial 1, with CA basic constraints and
  certificate/CRL signing key usage.
- `gost256-leaf.der`: leaf issued by that CA, serial 3, with an independent key.
- `gost256-delegate.der`: delegated responder, serial 4, with digitalSignature
  key usage and id-kp-OCSPSigning.
- `gost256-ocsp-ca-good.der`: good status for the leaf, signed by the issuer.
- `gost256-ocsp-delegated-good.der`: good status signed by the delegated key,
  embedding its certificate.
- `gost256-ocsp-without-eku.der`: signed by the same delegated key but embedding
  an issuer-signed certificate without id-kp-OCSPSigning.
- `gost256-ocsp-foreign-issuer.der`: signed by the same delegated key but
  embedding an OCSP responder certificate issued by another CA.
- `gost256-spki.der`: the issuer public key, exported as
  `gost256-ca.spki.der` by the generator.
- `gost256-message.bin`, `gost256-message.hash`, `gost256-message.sig`:
  a binary message containing NUL and UTF-8, its 32-byte SDK digest, and its
  64-byte SDK signature.

The two unauthorized responder fixtures have valid response signatures. They
exercise certificate role and issuer checks rather than corrupt cryptography.
All responses use ResponderID byKey, and their CertID identifies the leaf under
the original issuer.

Certificates are valid from 2019-01-01 through 2050-01-01. Signed OCSP producedAt
is 2020-01-01T00:00:00Z, thisUpdate is 2019-12-31T23:59:00Z, and nextUpdate is
2050-01-01T00:00:00Z. Status tests use a fixed 2030-01-01 clock; HTTP tests use
the current clock and these intervals until 2050. The broad intervals are test
data, not deployment guidance.

The public-key, curve, signature and digest OIDs are respectively
`1.2.398.3.10.1.1.2.1`, `1.2.398.3.10.1.1.2.1.1`,
`1.2.398.3.10.1.1.2.3.1` and `1.2.398.3.10.1.3.2`.
The SPKI contains an OCTET STRING with LE(X) followed by LE(Y). Signatures
contain LE(r) followed by LE(s). Independent Python integer arithmetic also
verified the public-key relation, subgroup membership and message signature
equation against the SDK output.
