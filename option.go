package kalkan

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

const (
	defaultTSAURL  = "http://tsp.pki.gov.kz:80"
	defaultOCSPURL = "http://ocsp.pki.gov.kz"

	// DefaultMaxOutputBufferSize limits each output buffer unless overridden
	// by WithMaxOutputBufferSize.
	DefaultMaxOutputBufferSize = ckalkan.DefaultMaxOutputBufferSize

	// DefaultOCSPTimeout bounds the complete HTTP exchange for WithCustomOCSP,
	// including reading the body. A shorter caller deadline takes precedence.
	DefaultOCSPTimeout = 15 * time.Second
)

type runtimeConfig struct {
	ocspURL         string
	customOCSP      bool
	ocspTimeout     time.Duration
	proxy           Proxy
	maxInputSize    int64
	atomicZIPOutput bool
	endpointPolicy  *EndpointPolicy
	observer        Observer
}

type config struct {
	proxy               *Proxy
	logger              *slog.Logger
	endpointPolicy      *EndpointPolicy
	observer            Observer
	libraryPath         string
	java                javaConfig
	tsaURL              string
	ocspURL             string
	trusted             []TrustedCertificate
	ocspTimeout         time.Duration
	maxInputSize        int64
	maxOutputBufferSize int
	customOCSP          bool
	atomicZIPOutput     bool
}

// Option configures Open.
type Option func(*config)

// WithLibraryPath sets the absolute KalkanCrypt shared-library path.
func WithLibraryPath(path string) Option {
	return func(c *config) {
		c.libraryPath = path
	}
}

// WithTSAURL overrides the timestamp authority endpoint.
func WithTSAURL(url string) Option {
	return func(c *config) {
		c.tsaURL = url
	}
}

// WithOCSPURL overrides the OCSP endpoint used by ValidateCertificate when the
// request does not specify RevocationSource. It is also the default responder
// for Java CMS, XML and ZIP verification.
func WithOCSPURL(url string) Option {
	return func(c *config) {
		c.ocspURL = url
	}
}

// WithCustomOCSP enables Go OCSP requests and signature verification for
// CertificateValidationOCSP. By default, OCSP uses KalkanCrypt's native path.
// Native chain validation still runs before the Go OCSP check. The issuer must
// be available through loaded certificates or ValidateCertificateRequest.Issuer.
// A Go OCSP failure never falls back to native OCSP.
// Requires the native backend; Java uses its own OCSP implementation.
func WithCustomOCSP() Option {
	return func(c *config) {
		c.customOCSP = true
	}
}

// WithOCSPTimeout bounds HTTP requests when WithCustomOCSP is enabled. Zero selects
// DefaultOCSPTimeout; negative values make Open return ErrInvalidInput.
// This option does not enable Go OCSP or limit native calls. Use process
// isolation for native deadlines.
func WithOCSPTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.ocspTimeout = timeout
	}
}

// WithEndpointPolicy restricts TSA and OCSP URLs, including per-request OCSP
// overrides. By default destinations are unrestricted. Go OCSP rejects redirects;
// native redirects and DNS rebinding still require external egress controls.
func WithEndpointPolicy(policy EndpointPolicy) Option {
	owned := policy.clone()

	return func(c *config) {
		c.endpointPolicy = owned.clone()
	}
}

// WithTrustedCertificate loads a trusted certificate during Open.
// Certificates stay trusted until Close, including across LoadKeyStore calls.
// See TrustedCertificate for byte ownership and file lifetime requirements.
func WithTrustedCertificate(cert TrustedCertificate) Option {
	return func(c *config) {
		c.trusted = append(c.trusted, cert)
	}
}

// WithMaxInputSize limits in-memory inputs and files read by the Go wrapper.
// It does not limit files read directly by the native SDK or PKCS12 containers
// loaded by the Java provider. Values less than or equal to zero disable this
// limit; backend-specific protocol and archive limits still apply.
func WithMaxInputSize(size int64) Option {
	return func(c *config) {
		c.maxInputSize = max(size, 0)
	}
}

// WithMaxOutputBufferSize limits each native output buffer or Java result field.
// Zero selects DefaultMaxOutputBufferSize. Positive values must fit in a signed
// 32-bit integer. A negative value makes Open return ErrInvalidInput.
func WithMaxOutputBufferSize(size int) Option {
	return func(c *config) {
		c.maxOutputBufferSize = size
	}
}

// WithProxy configures backend and optional Go OCSP HTTP proxy settings during Open.
func WithProxy(proxy Proxy) Option {
	return func(c *config) {
		c.proxy = &proxy
	}
}

// WithAtomicZIPOutput makes SignZIP create its output in a private temporary
// directory next to OutputPath, then publish the completed file atomically
// without replacing an existing destination. It requires a filesystem that
// supports hard links and an output directory controlled by the application.
// By default SignZIP lets KalkanCrypt create OutputPath directly.
func WithAtomicZIPOutput() Option {
	return func(c *config) {
		c.atomicZIPOutput = true
	}
}

// WithLogger enables diagnostic structured logging for Client operations.
// Passing nil leaves logging disabled. The logger receives a component=kalkan
// attribute and is never installed as slog's process-global default logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		c.logger = logger
	}
}

// WithObserver installs an optional callback for operation timings and safe
// outcome metadata. It runs after the client call gate is released; see Observer
// for concurrency and Close behavior. Passing nil disables observations.
func WithObserver(observer Observer) Option {
	return func(c *config) {
		c.observer = observer
	}
}

func defaultOpenConfig() config {
	return config{
		tsaURL:  defaultTSAURL,
		ocspURL: defaultOCSPURL,
	}
}

func (c *config) validate() error {
	if c.ocspTimeout < 0 {
		return fmt.Errorf("%w: OCSP timeout must be non-negative", ErrInvalidInput)
	}

	if c.maxOutputBufferSize < 0 {
		return fmt.Errorf("%w: maximum output buffer size must be non-negative", ErrInvalidInput)
	}

	if c.endpointPolicy != nil {
		if err := c.endpointPolicy.validate(); err != nil {
			return err
		}
	}

	if err := c.validateBackend(); err != nil {
		return err
	}

	endpointPolicy := c.startupEndpointPolicy()

	tsaURL, err := normalizeNativeHTTPURLWithPolicy("TSA URL", c.tsaURL, endpointPurposeTSA, endpointPolicy)
	if err != nil {
		return err
	}

	c.tsaURL = tsaURL

	ocspURL, err := normalizeNativeHTTPURLWithPolicy("OCSP URL", c.ocspURL, endpointPurposeOCSP, endpointPolicy)
	if err != nil {
		return err
	}

	c.ocspURL = ocspURL

	if c.proxy != nil {
		if err := c.proxy.validate(); err != nil {
			return err
		}
	}

	return nil
}

func (c config) runtime() runtimeConfig {
	var proxy Proxy
	if c.proxy != nil {
		proxy = *c.proxy
	}

	return runtimeConfig{
		ocspURL:         c.ocspURL,
		customOCSP:      c.customOCSP,
		ocspTimeout:     c.ocspTimeout,
		proxy:           proxy,
		maxInputSize:    c.maxInputSize,
		atomicZIPOutput: c.atomicZIPOutput,
		endpointPolicy:  cloneEndpointPolicy(c.endpointPolicy),
		observer:        c.observer,
	}
}

func cloneEndpointPolicy(policy *EndpointPolicy) *EndpointPolicy {
	if policy == nil {
		return nil
	}

	return policy.clone()
}

func (c config) runtimeLogger() *slog.Logger {
	if c.logger == nil {
		return nil
	}

	return c.logger.With("component", "kalkan")
}
