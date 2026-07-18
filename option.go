package kalkan

import (
	"fmt"
	"log/slog"
	"path/filepath"
)

const (
	defaultTSAURL  = "http://tsp.pki.gov.kz:80"
	defaultOCSPURL = "http://ocsp.pki.gov.kz"
)

type runtimeConfig struct {
	ocspURL      string
	maxInputSize int64
}

type config struct {
	libraryPath         string
	tsaURL              string
	ocspURL             string
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
		tsaURL:  defaultTSAURL,
		ocspURL: defaultOCSPURL,
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

	tsaURL, err := normalizeNativeHTTPURL("TSA URL", c.tsaURL)
	if err != nil {
		return err
	}

	c.tsaURL = tsaURL

	ocspURL, err := normalizeNativeHTTPURL("OCSP URL", c.ocspURL)
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
