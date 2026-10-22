package ckalkan

import (
	"errors"
	"fmt"
	"sync"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

var (
	// ErrAlreadyOpen indicates that another Client is still active in this process.
	ErrAlreadyOpen = errors.New("ckalkan: KalkanCrypt client is already open")

	// ErrClosed indicates a method call after Close.
	ErrClosed = errors.New("ckalkan: client is closed")

	// ErrNoLibrary indicates that New received no library path.
	ErrNoLibrary = errors.New("ckalkan: no KalkanCrypt library path")

	// ErrUnavailable indicates that the current build has no native KalkanCrypt loader.
	ErrUnavailable = errors.New("ckalkan: native KalkanCrypt loader is unavailable for this build")

	// ErrInvalidOutputBufferSize indicates a negative WithMaxBufferSize limit.
	// Zero selects DefaultMaxOutputBufferSize.
	ErrInvalidOutputBufferSize = errors.New("ckalkan: maximum output buffer size must be non-negative")

	// ErrPoisoned indicates that native cleanup failed and the process cannot
	// safely reuse KalkanCrypt state.
	ErrPoisoned = errors.New("ckalkan: KalkanCrypt process state is poisoned after failed close")
)

// clientContext defines the internal/kalkancrypt capabilities that Client requires.
// Tests use this interface to supply fakes without a native library.
type clientContext interface {
	Close() error
	ClearError()
	LastErrorString(capacity int) (kalkancrypt.BufferResult, error)
}

type lifecycleContext interface {
	Init() uint64
	InitDebug()
	Finalize()
	XMLFinalize()
	LastError() uint64
}

type tokenStoreContext interface {
	GetTokens(storage uint64, capacity int) (kalkancrypt.ListResult, error)
	GetCertificatesList(capacity int) (kalkancrypt.ListResult, error)
	LoadKeyStore(storage int, password, container, alias string) uint64
}

type x509Context interface {
	X509LoadCertificateFromFile(certPath string, certType int) uint64
	X509LoadCertificateFromBuffer(cert []byte, format int) uint64
	X509ExportCertificateFromStore(alias string, format, capacity int) (kalkancrypt.BufferResult, error)
	X509CertificateGetInfo(cert []byte, prop, capacity int) (kalkancrypt.BufferResult, error)
	X509ValidateCertificate(call kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error)
}

type hashContext interface {
	HashData(call kalkancrypt.HashDataCall) (kalkancrypt.BufferResult, error)
	SignHash(call kalkancrypt.SignHashCall) (kalkancrypt.BufferResult, error)
}

type cmsContext interface {
	LastError() uint64
	SignData(call kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error)
	VerifyData(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error)
	GetTimeFromSig(data []byte, flags, sigID int) (uint64, int64)
	GetCertFromCMS(call kalkancrypt.GetCertFromCMSCall) (kalkancrypt.BufferResult, error)
}

type xmlContext interface {
	SignXML(call kalkancrypt.SignXMLCall) (kalkancrypt.BufferResult, error)
	SignWSSE(call kalkancrypt.SignWSSECall) (kalkancrypt.BufferResult, error)
	VerifyXML(call kalkancrypt.VerifyXMLCall) (kalkancrypt.BufferResult, error)
	GetCertFromXML(xml []byte, signID, capacity int) (kalkancrypt.BufferResult, error)
	GetSigAlgFromXML(xml []byte, capacity int) (kalkancrypt.BufferResult, error)
}

type networkContext interface {
	SetTSAURL(tsaURL string) uint64
	SetProxy(call kalkancrypt.ProxyCall) uint64
}

type zipContext interface {
	ZipConVerify(zipFile string, flags, capacity int) (kalkancrypt.BufferResult, error)
	ZipConSign(call kalkancrypt.ZipConSignCall) uint64
	GetCertFromZipFile(call kalkancrypt.GetCertFromZipFileCall) (kalkancrypt.BufferResult, error)
}

// processState protects KalkanCrypt state across the process.
//
// The native library exposes no independent context handle per operation.
// Loaded keys, XML state, network settings, and error text are global to the loaded library.
// One mutex protects both the active client slot and each native call.
type processState struct {
	mu       sync.Mutex
	active   bool
	poisoned bool
}

//nolint:gochecknoglobals
var process processState

// Client controls one loaded KalkanCrypt library and its state.
//
// KalkanCrypt shares loaded keys, XML state, network settings, and error text
// across the process.
// The package allows one active Client per process.
// A process mutex serializes public methods.
// Use separate OS processes for parallel native calls.
//
// A Client is safe for concurrent method calls.
// Synchronize sequences that load a key store and then sign with it.
// Create clients with [New].
// Call [Client.Init] before cryptographic operations.
// The zero value is not ready for use.
// Do not copy a Client.
//
// Share the pointer returned by New.
type Client struct {
	noCopy   noCopy
	ctx      clientContext
	config   config
	closed   bool
	ownsSlot bool
}

// noCopy makes go vet report accidental copies of a Client.
type noCopy struct{}

// Lock is a no-op for go vet's copy checks.
func (*noCopy) Lock() {}

// Unlock is a no-op for go vet's copy checks.
func (*noCopy) Unlock() {}

// New loads KalkanCrypt and resolves its KC_GetFunctionList table.
// It does not call KC_Init.
// Call [Client.Init] before cryptographic operations.
func New(options ...Option) (*Client, error) {
	cfg := defaultConfig()

	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}

	if cfg.maxBufferSize < 0 {
		return nil, ErrInvalidOutputBufferSize
	}

	libraryPath := cfg.libraryPath
	if libraryPath == "" {
		return nil, ErrNoLibrary
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	if process.poisoned {
		return nil, ErrPoisoned
	}

	if process.active {
		return nil, ErrAlreadyOpen
	}

	process.active = true
	keepSlot := false

	defer func() {
		if !keepSlot {
			process.active = false
		}
	}()

	ctx, err := kalkancrypt.Open(libraryPath)
	if err == nil {
		keepSlot = true

		return &Client{ctx: ctx, config: cfg, ownsSlot: true}, nil
	}

	if errors.Is(err, kalkancrypt.ErrUnavailable) {
		return nil, ErrUnavailable
	}

	return nil, fmt.Errorf("ckalkan: cannot load KalkanCrypt library: %s: %w", libraryPath, err)
}

// Close releases native XML and core resources and closes the dynamic library
// handle.
// Later calls return nil after the first close attempt.
// Close returns nil for a nil client.
func (c *Client) Close() (err error) {
	if c == nil {
		return nil
	}

	process.mu.Lock()
	defer process.mu.Unlock()

	if c.closed || c.ctx == nil {
		c.closed = true

		if c.ownsSlot && !process.poisoned {
			process.active = false
			c.ownsSlot = false
		}

		return nil
	}

	if lifecycle, ok := c.ctx.(lifecycleContext); ok {
		lifecycle.XMLFinalize()
		lifecycle.Finalize()
	} else {
		err = unsupportedContextCapability("Close")
	}

	if closeErr := c.ctx.Close(); closeErr != nil {
		process.poisoned = true
		c.ctx = nil
		c.closed = true

		return errors.Join(err, fmt.Errorf("ckalkan: %w", closeErr))
	}

	c.ctx = nil
	c.closed = true

	if c.ownsSlot {
		process.active = false
		c.ownsSlot = false
	}

	return err
}

func (c *Client) ensureOpenLocked() error {
	if c == nil {
		return ErrClosed
	}

	if c.closed || c.ctx == nil {
		if !kalkancrypt.Available() {
			return ErrUnavailable
		}

		return ErrClosed
	}

	return nil
}

func (c *Client) clearErrorLocked() {
	if c != nil && c.ctx != nil {
		c.ctx.ClearError()
	}
}

// contextAsLocked checks the client state and retrieves the required native
// capability. The caller must hold process.mu throughout its use.
func contextAsLocked[T any](c *Client, operation string) (T, error) {
	var zero T

	if err := c.ensureOpenLocked(); err != nil {
		return zero, err
	}

	capability, ok := any(c.ctx).(T)
	if !ok {
		return zero, unsupportedContextCapability(operation)
	}

	return capability, nil
}

func unsupportedContextCapability(operation string) error {
	return fmt.Errorf("ckalkan: native context does not support %s", operation)
}
