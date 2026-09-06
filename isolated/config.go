package isolated

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/skarm/kalkan"
)

// Config configures a dedicated local worker process. Its zero value is invalid:
// WorkerPath and LibraryPath must be absolute paths without NUL bytes. Library
// options have the same defaults as [kalkan.Open]. The worker inherits the
// environment and working directory at [Open]; relative file paths refer to that
// directory throughout its lifetime. The worker must use the same build as this
// client; running the application's own executable ensures this.
type Config struct {
	// WorkerPath is the absolute path to an executable that calls [RunWorker].
	// Use os.Executable to run the application's own binary in worker mode.
	WorkerPath string
	// WorkerArgs selects the application's worker entry point, for example
	// []string{"--kalkan-worker"}. Arguments are passed directly without a shell.
	// Nil passes no arguments. Do not include passwords or other SDK settings;
	// Open sends those over the private protocol pipes.
	WorkerArgs []string
	// LibraryPath is the absolute path to the KalkanCrypt shared library.
	LibraryPath string
	// TSAURL overrides the timestamp authority endpoint. Nil selects the
	// default; a pointer to an empty string explicitly sets an empty URL.
	// See [kalkan.WithTSAURL].
	TSAURL *string
	// OCSPURL overrides the default OCSP endpoint. Nil selects the default;
	// a pointer to an empty string explicitly sets an empty URL.
	// See [kalkan.WithOCSPURL].
	OCSPURL *string
	// Proxy configures the native HTTP proxy during startup. Nil omits proxy
	// configuration. See [kalkan.WithProxy].
	Proxy *kalkan.Proxy
	// TrustedCertificates are loaded during startup and retained until Close.
	// See [kalkan.TrustedCertificate] for byte ownership and file lifetimes.
	TrustedCertificates []kalkan.TrustedCertificate
	// MaxInputSize limits each in-memory input before sending it to the worker,
	// which also applies the root client's input checks. Values less than or equal
	// to zero disable this limit. See [kalkan.WithMaxInputSize] for file inputs.
	MaxInputSize int64
	// MaxOutputBufferSize caps each native output buffer in bytes. Zero uses
	// [kalkan.DefaultMaxOutputBufferSize]; negative values are invalid.
	MaxOutputBufferSize int
	// AtomicZIPOutput publishes completed ZIP files without replacing existing
	// destinations. See [kalkan.WithAtomicZIPOutput] for filesystem requirements.
	AtomicZIPOutput bool
	// EndpointPolicy restricts TSA and OCSP URLs. Nil leaves them unrestricted.
	// See [kalkan.WithEndpointPolicy] for the scope of these checks.
	EndpointPolicy *kalkan.EndpointPolicy
	// Logger receives safe operation metadata in the parent. Native stdout and
	// stderr are discarded; payloads and native error text are never logged.
	Logger *slog.Logger
	// Observer receives SDK observations returned by the worker, after the IPC
	// call gate is released. Timings are measured in the worker. A killed worker
	// cannot return its unfinished observations. Callbacks must return promptly.
	Observer kalkan.Observer
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

	return nil
}

func (cfg Config) libraryConfig() libraryConfig {
	return libraryConfig{
		CollectObservations: cfg.Observer != nil,
		LibraryPath:         cfg.LibraryPath, TSAURL: cfg.TSAURL, OCSPURL: cfg.OCSPURL,
		Proxy: cfg.Proxy, TrustedCertificates: cfg.TrustedCertificates,
		MaxInputSize: cfg.MaxInputSize, MaxOutputBufferSize: cfg.MaxOutputBufferSize,
		AtomicZIPOutput: cfg.AtomicZIPOutput, EndpointPolicy: cfg.EndpointPolicy,
	}
}
