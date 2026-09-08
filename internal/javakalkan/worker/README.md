# Java worker

This directory owns the embedded JVM program. `sources.go` writes the source tree into a private directory for each client session. The proprietary provider and optional XML dependencies are supplied by the caller and are never embedded.

`src/Bootstrap.java` uses the JDK source launcher and the standard `JavaCompiler` API to compile the separate `kalkan.worker` classes with Java 17 compatibility. It then starts `Main` inside the same JVM. No build tool, separate compiler process, generated source concatenation or prebuilt artifact is needed. Canceling the owning Go operation terminates the JVM during compilation or execution; closing the client removes its source and class files.

The worker separates responsibilities:

- `Main` initializes the provider and hands the original standard streams to `Protocol`.
- `Protocol` owns binary framing, response size limits and callbacks to Go; `Arguments` and `Failure` define the shared argument/error contract. The crypto classes use `EvidenceFetcher` for revocation and timestamp requests; URL policy and HTTP transport remain in Go.
- `Session` routes operations and owns the per-client components.
- `KeyStoreState` owns private keys and their certificate chains. Loading a keystore leaves trusted certificates unchanged.
- `CertificateValidation` owns trusted certificates, PKIX path building, revocation policy and the per-operation evidence cache. `CertificateWithoutTimeCheck` adapts certificates for explicit validity-check opt-out. `OcspValidation` checks responses and responder authorization; `CrlValidation` selects and checks applicable CRLs.
- `CmsOperations` signs, verifies and extracts CMS data. `CmsSupport` handles signer ordering, certificate selection and signed attributes; `TimestampOperations` requests and validates signature timestamps. `CryptoSupport` contains shared algorithm selection and ASN.1 parsing.
- `XmlOperations` coordinates XML/WSSE operations behind `XmlSupport`. `XmlDocument` owns safe DOM parsing, IDs and placement; `XmlSignatures` owns signature structure, signer selection and cryptographic verification. These three sources are included in compilation only when XML JARs are configured. Provider-only sessions do not compile or load Santuario classes and report XML operations as unsupported.

The process protocol is private to this Go module and its embedded worker. The parent Go package owns both test layers: `*_sdk_test.go` uses the public API from external package `javakalkan_test`; SDK-independent tests exercise transport framing, cancellation and file/network behavior from package `javakalkan`. Shared fixtures remain in `internal/testfixture`.

Use four-space indentation, explicit imports and braces for control-flow bodies. Keep protocol argument decoding in the dispatch layer, and name the stages of cryptographic operations in separate methods. Request records group related options; they do not change the binary protocol or the public Go API.

Format Java sources with [google-java-format 1.36.1](https://github.com/google/google-java-format/releases/tag/v1.36.1) in AOSP mode. From the repository root, run `make fmt-java` with the formatter on `PATH`, or provide its command explicitly:

```sh
make fmt-java JAVA_FORMAT='java -jar /path/to/google-java-format-1.36.1-all-deps.jar'
```

The formatter is a development tool and is not required to build or run the worker.
