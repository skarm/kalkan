package kalkan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

const maxSignerID = int(^uint32(0) >> 1)

// Client owns one initialized KalkanCrypt session.
//
// KalkanCrypt stores process-global state inside the native library. The
// low-level ckalkan package therefore allows one active native client per
// process and serializes native calls. Client follows that model.
type Client struct {
	mu      sync.Mutex
	gate    chan struct{}
	closing *closeState
	library closer
	config  runtimeConfig
	logger  *slog.Logger
}

type closeState struct {
	done chan struct{}
	err  error
}

type closer interface {
	Close() error
}

type initializer interface {
	Init() error
}

type network interface {
	SetTSAURL(tsaURL string) error
	SetProxy(req ckalkan.ProxyRequest) error
}

type hashing interface {
	HashData(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error)
	SignHash(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error)
}

type cmsSignatures interface {
	SignData(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error)
	VerifyData(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error)
	GetCertFromCMS(data []byte, signID int, flags ckalkan.Flag) ([]byte, error)
	GetTimeFromSig(data []byte, flags ckalkan.Flag, sigID int) (time.Time, error)
}

type xmlSignatures interface {
	SignXML(req ckalkan.SignXMLRequest) ([]byte, error)
	VerifyXML(alias string, flags ckalkan.Flag, xml []byte) (string, error)
	SignWSSE(req ckalkan.SignWSSERequest) ([]byte, error)
	GetCertFromXML(xml []byte, signID int) ([]byte, error)
	GetSigAlgFromXML(xml []byte) (string, error)
}

type certificates interface {
	X509ValidateCertificate(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error)
	X509ExportCertificateFromStore(alias string, format ckalkan.CertFormat) ([]byte, error)
	X509CertificateGetInfo(cert []byte, prop ckalkan.CertProp) ([]byte, error)
	X509LoadCertificateFromBuffer(cert []byte, format ckalkan.CertFormat) error
	X509LoadCertificateFromFile(certPath string, certType ckalkan.CertType) error
}

type keyStore interface {
	LoadKeyStore(storage ckalkan.Store, password, container, alias string) error
}

type zipContainers interface {
	ZipConSign(req ckalkan.ZipConSignRequest) error
	ZipConVerify(zipFile string, flags ckalkan.Flag) (string, error)
	GetCertFromZipFile(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error)
}

// Open loads and initializes KalkanCrypt.
//
// The context is checked before and between Go setup steps and while waiting to
// enter a native call, including waiting for the native call serialization lock.
// It cannot interrupt a KalkanCrypt call after control has entered the shared
// library.
func Open(ctx context.Context, options ...Option) (*Client, error) {
	return openWithLibraryFactory(ctx, options, defaultLibraryFactory)
}

// Close releases the native KalkanCrypt session. It may be called more than once.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}

	start := time.Now()

	c.mu.Lock()

	if c.closing != nil {
		closing := c.closing
		c.mu.Unlock()

		<-closing.done

		return closing.err
	}

	library := c.library
	if library == nil {
		c.mu.Unlock()

		return nil
	}

	closing := &closeState{done: make(chan struct{})}
	c.closing = closing
	gate := c.libraryGateLocked()
	c.mu.Unlock()

	<-gate

	err := library.Close()

	c.mu.Lock()
	c.library = nil
	closing.err = err
	close(closing.done)
	c.closing = nil
	c.mu.Unlock()

	gate <- struct{}{}

	logNativeCall(c, context.Background(), "Close", start, err)

	return err
}

func (c *Client) lockLibrary(ctx context.Context) (closer, func(), error) {
	if c == nil {
		return nil, nil, ErrClosed
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	c.mu.Lock()
	if c.library == nil || c.closing != nil {
		c.mu.Unlock()

		return nil, nil, ErrClosed
	}

	gate := c.libraryGateLocked()
	c.mu.Unlock()

	select {
	case <-gate:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	if err := ctx.Err(); err != nil {
		gate <- struct{}{}
		return nil, nil, err
	}

	c.mu.Lock()
	library := c.library

	if library == nil || c.closing != nil {
		c.mu.Unlock()

		gate <- struct{}{}

		return nil, nil, ErrClosed
	}
	c.mu.Unlock()

	return library, func() { gate <- struct{}{} }, nil
}

func (c *Client) libraryGateLocked() chan struct{} {
	if c.gate == nil {
		c.gate = make(chan struct{}, 1)
		c.gate <- struct{}{}
	}

	return c.gate
}

type libraryFactory func(config) (closer, error)

func defaultLibraryFactory(cfg config) (closer, error) {
	options := []ckalkan.Option{ckalkan.WithLibrary(cfg.libraryPath)}
	if cfg.maxOutputBufferSize > 0 {
		options = append(options, ckalkan.WithMaxBufferSize(cfg.maxOutputBufferSize))
	}

	low, err := ckalkan.New(options...)
	if err != nil {
		if errors.Is(err, ckalkan.ErrUnavailable) {
			return nil, ErrUnavailable
		}

		return nil, err
	}

	return low, nil
}

func openWithLibraryFactory(ctx context.Context, options []Option, factory libraryFactory) (_ *Client, err error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cfg := defaultOpenConfig()

	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	cfg.applyEnvironmentDefaults()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	library, err := factory(cfg)
	if err != nil {
		return nil, err
	}

	client := &Client{library: library, config: cfg.runtime(), logger: cfg.runtimeLogger()}
	keepOpen := false

	defer func() {
		if !keepOpen {
			if closeErr := client.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}
	}()

	if err := setupOpenedClient(ctx, client, cfg); err != nil {
		return nil, err
	}

	for _, cert := range cfg.trusted {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if err := client.LoadTrustedCertificate(ctx, cert); err != nil {
			return nil, err
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	keepOpen = true

	return client, nil
}

func setupOpenedClient(ctx context.Context, client *Client, cfg config) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := withLockedLibrary(client, ctx, "Init", func(native initializer) error {
		return native.Init()
	}); err != nil {
		return fmt.Errorf("kalkan: initialize native library: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if cfg.tsaURL != "" {
		if err := withLockedLibrary(client, ctx, "SetTSAURL", func(native network) error {
			return native.SetTSAURL(cfg.tsaURL)
		}); err != nil {
			return fmt.Errorf("kalkan: configure TSA URL: %w", err)
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// There is no KalkanCrypt SetOCSPURL call in the SDK used by this wrapper;
	// cfg.ocspURL is consumed later by ValidateCertificate defaults.

	if cfg.proxy != nil {
		if err := withLockedLibrary(client, ctx, "SetProxy", func(native network) error {
			return native.SetProxy(cfg.proxy.native())
		}); err != nil {
			return fmt.Errorf("kalkan: configure proxy: %w", err)
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return nil
}

// withLockedLibrary holds the process-global call gate only while call runs.
func withLockedLibrary[T any](c *Client, ctx context.Context, operation string, call func(T) error) error {
	if ctx == nil {
		ctx = context.Background()
	}

	start := time.Now()

	library, unlock, err := c.lockLibrary(ctx)
	if err != nil {
		logNativeCall(c, ctx, operation, start, err)

		return err
	}
	defer unlock()

	capability, ok := any(library).(T)
	if !ok {
		err = unsupportedLibraryCapability(operation)
		logNativeCall(c, ctx, operation, start, err)

		return err
	}

	err = call(capability)
	logNativeCall(c, ctx, operation, start, err)

	return err
}

// withLockedLibraryResult holds the process-global call gate only while call runs.
func withLockedLibraryResult[T any, N any](c *Client, ctx context.Context, operation string, call func(N) (T, error)) (T, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	start := time.Now()

	library, unlock, err := c.lockLibrary(ctx)
	if err != nil {
		logNativeCall(c, ctx, operation, start, err)

		var zero T

		return zero, err
	}
	defer unlock()

	capability, ok := any(library).(N)
	if !ok {
		err = unsupportedLibraryCapability(operation)
		logNativeCall(c, ctx, operation, start, err)

		var zero T

		return zero, err
	}

	result, err := call(capability)
	logNativeCall(c, ctx, operation, start, err)

	return result, err
}

func unsupportedLibraryCapability(operation string) error {
	return fmt.Errorf("kalkan: library does not support %s", operation)
}

func logNativeCall(c *Client, ctx context.Context, operation string, start time.Time, err error) {
	if c == nil || c.logger == nil {
		return
	}

	attrs := []slog.Attr{
		slog.String("operation", operation),
		slog.Duration("duration", time.Since(start)),
	}
	if err != nil {
		attrs = append(attrs, slog.Any("error", err))
		c.logger.LogAttrs(ctx, slog.LevelError, "kalkan native call failed", attrs...)

		return
	}

	c.logger.LogAttrs(ctx, slog.LevelDebug, "kalkan native call completed", attrs...)
}

func validateSignerID(field string, value int) error {
	if value < 0 {
		return fmt.Errorf("%w: %s must be non-negative", ErrInvalidInput, field)
	}

	if value > maxSignerID {
		return fmt.Errorf("%w: %s must be in range 0..%d", ErrInvalidInput, field, maxSignerID)
	}

	return nil
}
