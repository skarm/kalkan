package isolated

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/skarm/kalkan"
)

// Config configures a dedicated local worker process.
// Its zero value is invalid.
// WorkerPath and LibraryPath must be absolute paths without NUL bytes.
// Library options use the same defaults as [kalkan.Open].
//
// The worker inherits the environment and current directory when [Open]
// starts it.
// Relative file paths use that directory throughout the worker's lifetime.
// The worker and client must use the same build.
// Use the application's own executable to satisfy this requirement.
type Config struct {
	// TSAURL overrides the timestamp authority endpoint.
	// Nil selects the default.
	// A pointer to an empty string explicitly selects an empty URL.
	// See [kalkan.WithTSAURL].
	TSAURL *string
	// OCSPURL overrides the default OCSP endpoint.
	// Nil selects the default.
	// A pointer to an empty string explicitly selects an empty URL.
	// See [kalkan.WithOCSPURL].
	OCSPURL *string
	// Proxy configures the native HTTP proxy and optional Go OCSP HTTP proxy
	// during startup. Nil omits proxy configuration. See [kalkan.WithProxy].
	Proxy *kalkan.Proxy
	// EndpointPolicy restricts TSA and OCSP URLs. Nil leaves them unrestricted.
	// See [kalkan.WithEndpointPolicy] for the scope of these checks.
	EndpointPolicy *kalkan.EndpointPolicy
	// Logger receives operation metadata without payloads in the parent.
	// The worker discards native stdout and stderr.
	// Logs never contain payloads or native error text.
	Logger *slog.Logger
	// Observer receives SDK observations from the worker after the parent
	// releases the IPC call gate.
	// The worker measures durations.
	// A killed worker cannot return unfinished observations.
	// The [kalkan.Observer] concurrency and callback requirements also apply
	// here.
	Observer kalkan.Observer
	// WorkerPath is the absolute path to an executable that calls [RunWorker].
	// Use os.Executable to run the application's own binary in worker mode.
	WorkerPath string
	// LibraryPath is the absolute path to the KalkanCrypt shared library.
	LibraryPath string
	// WorkerArgs selects the application's worker entry point, for example
	// []string{"--kalkan-worker"}.
	// Open passes arguments directly without a shell.
	// Nil passes no arguments.
	// Keep passwords and other SDK settings outside WorkerArgs.
	// Open sends those settings over private protocol pipes.
	WorkerArgs []string
	// TrustedCertificates supplies certificates for the worker's initial trust
	// store.
	// The worker retains successful loads until Close.
	// See [kalkan.TrustedCertificate] for byte ownership and file lifetimes.
	TrustedCertificates []kalkan.TrustedCertificate
	// OCSPTimeout limits each Go OCSP HTTP request, including the response body
	// read.
	// Zero uses [kalkan.DefaultOCSPTimeout].
	// Negative values are invalid.
	// This field does not enable CustomOCSP or limit native OCSP calls.
	OCSPTimeout time.Duration
	// MaxInputSize limits each in-memory input before transmission to the
	// worker.
	// The worker also applies the root client's input checks.
	// Values less than or equal to zero disable this limit.
	// See [kalkan.WithMaxInputSize] for file inputs.
	MaxInputSize int64
	// MaxOutputBufferSize limits each native output buffer in bytes.
	// Zero uses [kalkan.DefaultMaxOutputBufferSize].
	// Negative values are invalid.
	MaxOutputBufferSize int
	// CustomOCSP enables Go OCSP requests and signature verification in the worker.
	// False preserves native OCSP validation. See [kalkan.WithCustomOCSP].
	CustomOCSP bool
	// AtomicZIPOutput publishes completed ZIP files without replacement of
	// existing destinations.
	// See [kalkan.WithAtomicZIPOutput] for filesystem requirements.
	AtomicZIPOutput bool
}

func (cfg Config) validate() error {
	for _, path := range []string{cfg.WorkerPath, cfg.LibraryPath} {
		if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
			return fmt.Errorf("%w: absolute worker and library paths without NUL are required", kalkan.ErrInvalidInput)
		}
	}

	if cfg.MaxOutputBufferSize < 0 {
		return fmt.Errorf("%w: isolated output buffer limit must be non-negative", kalkan.ErrInvalidInput)
	}

	if cfg.OCSPTimeout < 0 {
		return fmt.Errorf("%w: OCSP timeout must be non-negative", kalkan.ErrInvalidInput)
	}

	return nil
}

func (cfg Config) libraryConfig() libraryConfig {
	return libraryConfig{
		CollectObservations: cfg.Observer != nil,
		LibraryPath:         cfg.LibraryPath, TSAURL: cfg.TSAURL, OCSPURL: cfg.OCSPURL, OCSPTimeout: cfg.OCSPTimeout,
		CustomOCSP: cfg.CustomOCSP,
		Proxy:      cfg.Proxy, TrustedCertificates: cfg.TrustedCertificates,
		MaxInputSize: cfg.MaxInputSize, MaxOutputBufferSize: cfg.MaxOutputBufferSize,
		AtomicZIPOutput: cfg.AtomicZIPOutput, EndpointPolicy: cfg.EndpointPolicy,
	}
}
