package kalkan

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/skarm/kalkan/ckalkan"
)

const (
	defaultTSAURL  = "http://tsp.pki.gov.kz:80"
	defaultOCSPURL = "http://ocsp.pki.gov.kz"

	// DefaultMaxOutputBufferSize is the default hard limit for each native
	// output buffer. It is a security and availability boundary, not a promise
	// that any operation should consume the full amount. Applications may set a
	// smaller limit with WithMaxOutputBufferSize.
	DefaultMaxOutputBufferSize = ckalkan.DefaultMaxOutputBufferSize
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
// before native calls. Values less than or equal to zero make memory inputs
// unlimited.
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
	if c.maxOutputBufferSize < 0 {
		return fmt.Errorf("%w: maximum output buffer size must be non-negative", ErrInvalidInput)
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
