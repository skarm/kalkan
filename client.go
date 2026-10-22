package kalkan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

const maxSignerID = int(^uint32(0) >> 1)

// Client owns one initialized KalkanCrypt session.
//
// KalkanCrypt shares native state across the process.
// The low-level ckalkan package allows one active native client per process.
// It serializes individual native calls.
// Client follows the same model.
//
// A Client is safe for concurrent method calls under the [Observer] callback contract.
// A sequence that loads a key store and then signs with it is not atomic.
// Synchronize the complete sequence when callers use different key stores.
// Separate processes can use different key stores independently.
//
// Create clients with [Open].
// The zero value is not ready for use.
type Client struct {
	mu       sync.Mutex
	pemCache atomic.Pointer[entry]
	gate     chan struct{}
	closing  *closeState
	library  closer
	config   runtimeConfig
	logger   *slog.Logger
	// The client accesses trusted only while it holds the native call gate.
	trusted []loadedTrustedCertificate
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
	SignData(req ckalkan.SignDataRequest) ([]byte, error)
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
// Open checks ctx before and between Go setup steps and during a wait for the client call gate.
// The context cannot interrupt the low-level process mutex wait, a library
// load, or an active native call, including Init.
// Cleanup after failed or canceled setup also waits without a context.
// A nil ctx uses [context.Background].
func Open(ctx context.Context, options ...Option) (*Client, error) {
	return openWithLibraryFactory(ctx, options, defaultLibraryFactory)
}

// Close releases the native KalkanCrypt session.
// It waits for an active native call to return before it closes the library.
// Repeated calls return the saved close result.
// Close returns nil for a nil client.
func (c *Client) Close() error {
	return c.CloseContext(context.Background())
}

// CloseContext starts native session shutdown and uses ctx to limit the caller's wait.
// It rejects new operations even if ctx is already canceled.
// A nil ctx uses [context.Background].
//
// Context cancellation can end the caller's wait while shutdown waits for
// another native call or runs in another goroutine.
// It cannot interrupt a KalkanCrypt call inside the shared library.
// Shutdown continues after the caller's wait ends.
//
// Repeated calls return the saved result after shutdown completes, even if ctx is canceled.
// CloseContext returns nil for a nil client.
func (c *Client) CloseContext(ctx context.Context) error {
	if c == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()

	if c.closing != nil {
		closing := c.closing
		c.mu.Unlock()

		return waitCloseContext(ctx, closing)
	}

	library := c.library
	if library == nil {
		c.pemCache.Store(nil)
		c.mu.Unlock()

		return nil
	}

	closing := &closeState{done: make(chan struct{})}
	c.closing = closing
	gate := c.libraryGateLocked()
	c.mu.Unlock()

	var start time.Time

	logCtx := context.Background()

	if c.logger != nil || c.config.observer != nil {
		start = time.Now()
		logCtx = context.WithoutCancel(ctx)
	}

	go c.closeLibrary(logCtx, library, gate, closing, start)

	return waitCloseContext(ctx, closing)
}

func (c *Client) closeLibrary(ctx context.Context, library closer, gate chan struct{}, closing *closeState, start time.Time) {
	<-gate

	var (
		nativeStart               time.Time
		queueWait, nativeDuration time.Duration
	)

	if !start.IsZero() {
		nativeStart = time.Now()
		queueWait = nativeStart.Sub(start)
	}

	var err error

	func() {
		defer releaseLibraryGate(gate)

		err = library.Close()

		if !start.IsZero() {
			nativeDuration = time.Since(nativeStart)
		}

		c.mu.Lock()
		c.library = nil
		c.trusted = nil
		c.pemCache.Store(nil)

		closing.err = err
		c.mu.Unlock()
	}()

	c.mu.Lock()
	close(closing.done)
	c.mu.Unlock()

	if !start.IsZero() {
		reportOperation(c, ctx, "Close", start, queueWait, nativeDuration, err)
	}
}

func waitCloseContext(ctx context.Context, closing *closeState) error {
	select {
	case <-closing.done:
		return closing.err
	default:
	}

	select {
	case <-closing.done:
		return closing.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// lockLibrary acquires the client call gate and checks that the session is still open.
// On success, release the returned gate after the library call.
func (c *Client) lockLibrary(ctx context.Context) (closer, chan struct{}, error) {
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

	if done := ctx.Done(); done == nil {
		<-gate
	} else {
		select {
		case <-gate:
		case <-done:
			return nil, nil, ctx.Err()
		}

		if err := ctx.Err(); err != nil {
			releaseLibraryGate(gate)

			return nil, nil, err
		}
	}

	c.mu.Lock()
	library := c.library

	if library == nil || c.closing != nil {
		c.mu.Unlock()

		releaseLibraryGate(gate)

		return nil, nil, ErrClosed
	}
	c.mu.Unlock()

	return library, gate, nil
}

func releaseLibraryGate(gate chan struct{}) {
	gate <- struct{}{}
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

	if err := withLockedLibrary(client, ctx, "SetTSAURL", func(native network) error {
		return native.SetTSAURL(cfg.tsaURL)
	}); err != nil {
		return fmt.Errorf("kalkan: configure TSA URL: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// This SDK has no SetOCSPURL call.
	// ValidateCertificate uses cfg.ocspURL as its default endpoint.

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

// withLockedLibrary holds the client call gate while call runs.
// It releases the gate before it reports observations.
// The low-level client serializes native calls through a separate process mutex.
func withLockedLibrary[T any](c *Client, ctx context.Context, operation string, call func(T) error) error {
	_, err := withLockedLibraryResult(c, ctx, operation, func(native T) (struct{}, error) {
		return struct{}{}, call(native)
	})

	return err
}

// withLockedLibraryResult runs call under the client call gate.
// It releases the gate before it reports observations.
// expectedCodes identifies accepted native statuses for diagnostics.
// It does not change the returned result or error.
func withLockedLibraryResult[T, N any](c *Client, ctx context.Context, operation string, call func(N) (T, error), expectedCodes ...ckalkan.ErrorCode) (T, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	diagnostics := c != nil && (c.logger != nil || c.config.observer != nil)

	var start time.Time
	if diagnostics {
		start = time.Now()
	}

	library, gate, err := c.lockLibrary(ctx)

	var queueWait, nativeDuration time.Duration
	if diagnostics {
		queueWait = time.Since(start)
	}

	var result T

	if err == nil {
		func() {
			defer releaseLibraryGate(gate)

			capability, ok := any(library).(N)
			if !ok {
				err = unsupportedLibraryCapability(operation)
				return
			}

			var nativeStart time.Time
			if diagnostics {
				nativeStart = time.Now()
			}

			result, err = call(capability)

			if diagnostics {
				nativeDuration = time.Since(nativeStart)
			}
		}()
	}

	if diagnostics {
		reportOperation(c, ctx, operation, start, queueWait, nativeDuration, err, expectedCodes...)
	}

	return result, err
}

func unsupportedLibraryCapability(operation string) error {
	return fmt.Errorf("kalkan: library does not support %s", operation)
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
