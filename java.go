package kalkan

import (
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strings"

	"github.com/skarm/kalkan/internal/javakalkan"
)

// JavaError describes a failure reported by the Java provider. It does not
// contain a native KalkanCrypt status code; use errors.As to inspect it.
type JavaError = javakalkan.Error

var (
	// ErrJavaUnsupported identifies operations unsupported by the Java backend.
	ErrJavaUnsupported = javakalkan.ErrUnsupported
	// ErrJavaWorkerFailed means the Java session ended or its protocol failed.
	// Open a new client to create a new session after this error.
	ErrJavaWorkerFailed = javakalkan.ErrWorkerFailed
)

// WithJavaProvider selects the Kalkan Java provider instead of a native shared
// library. Path must be an absolute path to the vendor's provider JAR. Requires
// a JDK with Java 17 or later. Each client owns one Java child process.
// Supports hashes, PKCS12, CMS, ZIP and certificate operations.
// XML/WS-Security operations additionally require WithJavaXMLLibraries.
// CMS verification checks revocation through OCSP by default and validates
// present RFC 3161 signature timestamps. See WithJavaRevocation for CRL/offline.
// It cannot be combined with WithLibraryPath. The vendor JAR is not bundled.
func WithJavaProvider(path string) Option {
	return func(c *config) { c.java.providerPath = path }
}

// WithJavaExecutable sets the Java launcher used with WithJavaProvider.
// An empty value uses "java" from PATH. A JDK launcher is required because
// the bootstrap compiles the embedded worker sources through the JDK compiler
// API in the same JVM. No separate javac executable is required.
func WithJavaExecutable(path string) Option {
	return func(c *config) { c.java.executable = path }
}

// WithJavaXMLLibraries enables Java XML/WS-Security signatures using the Kalkan
// XMLDSig adapter and Apache Santuario. Supply absolute paths to the adapter,
// xmlsec and its runtime dependencies. The provider-only backend remains usable
// without these optional JARs. Paths are copied when this option is created.
func WithJavaXMLLibraries(paths ...string) Option {
	owned := slices.Clone(paths)
	return func(c *config) { c.java.xmlLibraries = slices.Clone(owned) }
}

type javaConfig struct {
	providerPath string
	executable   string
	xmlLibraries []string
	revocation   *javaRevocationConfig
}

type javaRevocationConfig struct {
	mode   CertificateValidationMode
	source string
}

// WithJavaRevocation selects revocation checking for Java CMS, XML and ZIP verification,
// including timestamp authority chains. The default is OCSP using WithOCSPURL.
// OCSP source is a responder URL; CRL source is a file, directory, or HTTP(S)
// URL. An empty CRL source uses certificate distribution points. Every non-root
// certificate needs a current, authenticated good status; unavailable, unknown,
// stale or invalid evidence fails verification. No network fallback is implicit.
// CertificateValidationNone explicitly disables revocation checking, but keeps
// signature, trust-chain and timestamp checks. It is intended for offline use.
// Requires WithJavaProvider; it does not change native backend behavior or the
// mode explicitly selected by a standalone ValidateCertificate request.
func WithJavaRevocation(mode CertificateValidationMode, source string) Option {
	return func(c *config) { c.java.revocation = &javaRevocationConfig{mode, source} }
}

func (c *javaConfig) validate(maxOutputBufferSize int) error {
	for _, jar := range c.xmlLibraries {
		if !filepath.IsAbs(jar) || strings.ContainsAny(jar, "\x00"+string(filepath.ListSeparator)) {
			return fmt.Errorf("%w: Java XML library must be an absolute JAR path", ErrInvalidInput)
		}
	}

	path, err := validateNativePathString("Java provider path", c.providerPath)
	if err != nil {
		return err
	}

	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: absolute Java provider path is required", ErrInvalidInput)
	}

	if strings.ContainsRune(path, filepath.ListSeparator) {
		return fmt.Errorf("%w: Java provider path contains a classpath separator", ErrInvalidInput)
	}

	if err := rejectEmbeddedNUL("Java executable", c.executable); err != nil {
		return err
	}

	if maxOutputBufferSize > math.MaxInt32 {
		return fmt.Errorf("%w: Java output limit exceeds %d bytes", ErrInvalidInput, math.MaxInt32)
	}

	if c.revocation != nil {
		r := *c.revocation
		if _, err := r.mode.native(); err != nil {
			return err
		}

		if err := rejectEmbeddedNUL("Java revocation source", r.source); err != nil {
			return err
		}

		if r.mode == CertificateValidationNone && r.source != "" {
			return fmt.Errorf("%w: revocation source requires CRL or OCSP mode", ErrInvalidInput)
		}

		if r.source != "" && (r.mode == CertificateValidationOCSP || strings.Contains(r.source, "://")) {
			if _, err := normalizeNativeHTTPURL("Java revocation URL", r.source); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *javaConfig) requireProvider() error {
	if len(c.xmlLibraries) != 0 {
		return fmt.Errorf("%w: WithJavaXMLLibraries requires WithJavaProvider", ErrInvalidInput)
	}

	if c.revocation != nil {
		return fmt.Errorf("%w: WithJavaRevocation requires WithJavaProvider", ErrInvalidInput)
	}

	if c.executable != "" {
		return fmt.Errorf("%w: WithJavaExecutable requires WithJavaProvider", ErrInvalidInput)
	}

	return nil
}
