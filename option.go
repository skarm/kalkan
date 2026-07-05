package kalkan

import (
	"fmt"
	"log/slog"
	"path/filepath"
)

// Environment selects default KalkanCrypt network endpoints.
type Environment int

const (
	// ProductionEnvironment configures production network defaults.
	ProductionEnvironment Environment = iota
	// TestEnvironment configures test network defaults.
	TestEnvironment
)

const (
	defaultProductionTSA  = "http://tsp.pki.gov.kz:80"
	defaultProductionOCSP = "http://ocsp.pki.gov.kz"
	defaultTestTSA        = "http://test.pki.gov.kz/tsp/"
	defaultTestOCSP       = "http://test.pki.gov.kz/ocsp/"
)

type runtimeConfig struct {
	ocspURL      string
	maxInputSize int64
}

type config struct {
	libraryPath         string
	environment         Environment
	tsaURL              string
	tsaURLSet           bool
	ocspURL             string
	ocspURLSet          bool
	proxy               *Proxy
	trusted             []TrustedCertificate
	maxInputSize        int64
	maxOutputBufferSize int
	logger              *slog.Logger
}

// Option configures Open.
type Option func(*config)

// WithLibraryPath sets the absolute KalkanCrypt shared-library path.
func WithLibraryPath(path string) Option {
	return func(c *config) {
		c.libraryPath = path
	}
}

// WithEnvironment selects production or test endpoint defaults.
func WithEnvironment(environment Environment) Option {
	return func(c *config) {
		c.environment = environment
	}
}

// WithTSAURL overrides the timestamp authority endpoint.
func WithTSAURL(url string) Option {
	return func(c *config) {
		c.tsaURL = url
		c.tsaURLSet = true
	}
}

// WithOCSPURL overrides the OCSP endpoint used by ValidateCertificate when the
// request does not specify RevocationSource.
func WithOCSPURL(url string) Option {
	return func(c *config) {
		c.ocspURL = url
		c.ocspURLSet = true
	}
}

// WithTrustedCertificate loads a trusted certificate during Open.
func WithTrustedCertificate(cert TrustedCertificate) Option {
	return func(c *config) {
		c.trusted = append(c.trusted, cert)
	}
}

// WithMaxInputSize sets a byte limit for high-level in-memory byte inputs
// before native calls. Values less than or equal to zero leave memory inputs
// unlimited.
func WithMaxInputSize(size int64) Option {
	return func(c *config) {
		if size > 0 {
			c.maxInputSize = size
		}
	}
}

// WithMaxOutputBufferSize sets the hard cap used by the low-level KalkanCrypt
// output-buffer retry policy. Values less than or equal to zero keep the
// low-level default. Very small positive values are normalized by ckalkan to its
// conservative minimum output buffer size.
func WithMaxOutputBufferSize(size int) Option {
	return func(c *config) {
		if size > 0 {
			c.maxOutputBufferSize = size
		}
	}
}

// WithProxy configures KalkanCrypt's native HTTP proxy settings during Open.
func WithProxy(proxy Proxy) Option {
	return func(c *config) {
		c.proxy = &proxy
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

func defaultOpenConfig() config {
	return config{
		environment: ProductionEnvironment,
	}
}

func (c *config) validate() error {
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

	switch c.environment {
	case ProductionEnvironment, TestEnvironment:
	default:
		return fmt.Errorf("%w: unknown environment %d", ErrInvalidInput, c.environment)
	}

	if c.tsaURLSet {
		u, err := normalizeNativeHTTPURL("TSA URL", c.tsaURL)
		if err != nil {
			return err
		}

		c.tsaURL = u
	}

	if c.ocspURLSet {
		u, err := normalizeNativeHTTPURL("OCSP URL", c.ocspURL)
		if err != nil {
			return err
		}

		c.ocspURL = u
	}

	if c.proxy != nil {
		if err := c.proxy.validate(); err != nil {
			return err
		}
	}

	return nil
}

func (c *config) applyEnvironmentDefaults() {
	switch c.environment {
	case TestEnvironment:
		if c.tsaURL == "" {
			c.tsaURL = defaultTestTSA
		}

		if c.ocspURL == "" {
			c.ocspURL = defaultTestOCSP
		}
	default:
		if c.tsaURL == "" {
			c.tsaURL = defaultProductionTSA
		}

		if c.ocspURL == "" {
			c.ocspURL = defaultProductionOCSP
		}
	}
}

func (c config) runtime() runtimeConfig {
	return runtimeConfig{
		ocspURL:      c.ocspURL,
		maxInputSize: c.maxInputSize,
	}
}

func (c config) runtimeLogger() *slog.Logger {
	if c.logger == nil {
		return nil
	}

	return c.logger.With("component", "kalkan")
}
