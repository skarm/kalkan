package kalkan

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

const (
	defaultTSAURL  = "http://tsp.pki.gov.kz:80"
	defaultOCSPURL = "http://ocsp.pki.gov.kz"

	// DefaultMaxOutputBufferSize is the default hard limit for each native output buffer.
	// It bounds buffer growth for security and availability.
	// It does not require operations to consume the full amount.
	// Use [WithMaxOutputBufferSize] to set a smaller limit.
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
// request does not specify RevocationSource.
func WithOCSPURL(url string) Option {
	return func(c *config) {
		c.ocspURL = url
	}
}

// WithCustomOCSP enables Go OCSP requests and signature verification for
// [CertificateValidationOCSP].
// OCSP uses KalkanCrypt by default.
// Native chain validation runs before the Go OCSP check.
// Loaded certificates or ValidateCertificateRequest.Issuer must supply the
// issuer.
// If Go OCSP fails, the client returns the error without native OCSP
// fallback.
func WithCustomOCSP() Option {
	return func(c *config) {
		c.customOCSP = true
	}
}

// WithOCSPTimeout limits HTTP requests when [WithCustomOCSP] is enabled.
// Zero selects [DefaultOCSPTimeout].
// Negative values make [Open] return [ErrInvalidInput].
// This option does not enable Go OCSP or limit native calls.
// Use process isolation for native deadlines.
func WithOCSPTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.ocspTimeout = timeout
	}
}

// WithEndpointPolicy restricts TSA and OCSP URLs, including OCSP overrides in
// individual requests.
// The default configuration permits all destinations.
// Go OCSP rejects redirects.
// Native redirects and DNS rebinding require external network controls.
func WithEndpointPolicy(policy EndpointPolicy) Option {
	owned := policy.clone()

	return func(c *config) {
		c.endpointPolicy = owned.clone()
	}
}

// WithTrustedCertificate loads a trusted certificate during [Open].
// The client retains successful loads until Close and restores them after
// LoadKeyStore.
// See [TrustedCertificate] for byte ownership and file lifetime requirements.
func WithTrustedCertificate(cert TrustedCertificate) Option {
	return func(c *config) {
		c.trusted = append(c.trusted, cert)
	}
}

// WithMaxInputSize sets a byte limit for high-level in-memory byte inputs
// before native calls. It also bounds CMS files read by GetCertFromCMS and
// GetTimeFromSig, whose native operations require in-memory contents. Values
// less than or equal to zero disable this limit.
func WithMaxInputSize(size int64) Option {
	return func(c *config) {
		c.maxInputSize = max(size, 0)
	}
}

// WithMaxOutputBufferSize sets the hard cap for the low-level KalkanCrypt
// output-buffer retry policy. Zero restores DefaultMaxOutputBufferSize. A
// positive value selects a smaller or larger cap, subject to the native C int
// ABI maximum. A negative value makes Open return ErrInvalidInput.
func WithMaxOutputBufferSize(size int) Option {
	return func(c *config) {
		c.maxOutputBufferSize = size
	}
}

// WithProxy configures native and Go OCSP HTTP proxy settings during Open.
func WithProxy(proxy Proxy) Option {
	return func(c *config) {
		c.proxy = &proxy
	}
}

// WithAtomicZIPOutput makes [Client.SignZIP] create its output in a private
// temporary directory next to OutputPath.
// SignZIP then publishes the completed file atomically without replacement of
// an existing destination.
// This requires a filesystem with hard links and an output directory under
// application control.
// By default, KalkanCrypt creates OutputPath directly.
func WithAtomicZIPOutput() Option {
	return func(c *config) {
		c.atomicZIPOutput = true
	}
}

// WithLogger enables structured diagnostic logs for Client operations.
// A nil logger disables logs.
// The logger receives a component=kalkan attribute.
// This option does not set slog's default process logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		c.logger = logger
	}
}

// WithObserver sets an optional callback for native call durations and
// outcome metadata without payloads.
// The client releases the native gate before the callback runs.
// See [Observer] for concurrency and Close behavior.
// A nil observer disables observations.
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

	libraryPath, err := validateNativePathString("library path", c.libraryPath)
	if err != nil {
		if c.libraryPath == "" {
			return fmt.Errorf("%w: library path is required", ErrInvalidInput)
		}

		return err
	}

	if !filepath.IsAbs(libraryPath) {
		return fmt.Errorf("%w: absolute library path is required", ErrInvalidInput)
	}

	c.libraryPath = libraryPath

	tsaURL, err := normalizeNativeHTTPURLWithPolicy("TSA URL", c.tsaURL, endpointPurposeTSA, c.endpointPolicy)
	if err != nil {
		return err
	}

	c.tsaURL = tsaURL

	ocspURL, err := normalizeNativeHTTPURLWithPolicy("OCSP URL", c.ocspURL, endpointPurposeOCSP, c.endpointPolicy)
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
