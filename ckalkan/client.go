package ckalkan

import (
	"errors"
	"fmt"
	"sync"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

var (
	// ErrAlreadyOpen is returned when New is called while another Client is still
	// active in the same process.
	ErrAlreadyOpen = errors.New("ckalkan: KalkanCrypt client is already open")

	// ErrClosed is returned when a method is called after Close.
	ErrClosed = errors.New("ckalkan: client is closed")

	// ErrNoLibrary is returned when New has no library path to load.
	ErrNoLibrary = errors.New("ckalkan: no KalkanCrypt library path")

	// ErrUnavailable is returned when the current build has no native
	// KalkanCrypt loader.
	ErrUnavailable = errors.New("ckalkan: native KalkanCrypt loader is unavailable for this build")

	// ErrPoisoned is returned after native close/finalize failed and the
	// process-global KalkanCrypt state can no longer be reused.
	ErrPoisoned = errors.New("ckalkan: KalkanCrypt process state is poisoned after failed close")
)

// clientContext is the low-level call surface Client needs from internal/kalkancrypt.
// Tests use this interface to inject fakes without opening a native library.
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

// processState protects the process-global KalkanCrypt runtime state.
//
// The native library does not expose an independent context handle per operation:
// loaded keys, XML state, network settings, and last-error text all behave as
// global state inside the loaded .so. One mutex therefore guards both the single
// active-client slot and every call crossing the KalkanCrypt boundary.
type processState struct {
	mu       sync.Mutex
	active   bool
	poisoned bool
}

//nolint:gochecknoglobals
var process processState

// Client is a serialized, stateful handle to one loaded KalkanCrypt library.
//
// KalkanCrypt stores process-global state: loaded keys, XML state, network
// settings, and last-error text. For that reason ckalkan allows one active
// Client per process and serializes every public method through a process-wide
// mutex. If true parallelism is required, use separate OS processes.
type Client struct {
	ctx      clientContext
	config   config
	closed   bool
	ownsSlot bool
}

// New loads KalkanCrypt and resolves its KC_GetFunctionList table. It does not
// call KC_Init; call Init explicitly before cryptographic operations.
func New(options ...Option) (*Client, error) {
	cfg := defaultConfig()

	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
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

// Close finalizes XML/core KalkanCrypt state and closes the dynamic library
// handle. It may be called more than once.
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
