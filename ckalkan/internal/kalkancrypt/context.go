package kalkancrypt

// driver is the only platform-specific part of this package. Native drivers
// call a platform KalkanCrypt dynamic library; unsupported builds provide no
// driver and make Open return ErrUnavailable. Everything above this interface is
// ordinary Go and is compiled on every platform.
//
// Context and driver methods use call structures when the combined number of
// inputs and results would otherwise exceed five. Platform drivers unpack those
// structures only at the native ABI call site.
type driver interface {
	driverHandle
	driverLifecycle
	driverTokenStore
	driverX509
	driverCrypto
	driverXML
	driverCMS
	driverNetwork
	driverZIP
}

type driverHandle interface {
	Close() error
	ClearError()
}

type driverLifecycle interface {
	Init() uint64
	InitDebug()
	Finalize()
	XMLFinalize()
	LastError() uint64
	LastErrorString(capacity int) (BufferResult, error)
}

type driverTokenStore interface {
	GetTokens(storage uint64, bufferSize int) (ListResult, error)
	GetCertificatesList(bufferSize int) (ListResult, error)
	LoadKeyStore(storage int, password, container, alias string) uint64
}

type driverX509 interface {
	X509LoadCertificateFromFile(certPath string, certType int) uint64
	X509LoadCertificateFromBuffer(cert []byte, format int) uint64
	X509ExportCertificateFromStore(alias string, format, capacity int) (BufferResult, error)
	X509CertificateGetInfo(cert []byte, prop, capacity int) (BufferResult, error)
	X509ValidateCertificate(call ValidateCertificateCall) (ValidateResult, error)
}

type driverCrypto interface {
	HashData(call HashDataCall) (BufferResult, error)
	SignHash(call SignHashCall) (BufferResult, error)
	SignData(call SignDataCall) (BufferResult, error)
	SignXML(call SignXMLCall) (BufferResult, error)
	SignWSSE(call SignWSSECall) (BufferResult, error)
	VerifyData(call VerifyDataCall) (VerifyResult, error)
	UVerifyData(call VerifyDataCall) (VerifyResult, error)
}

type driverXML interface {
	VerifyXML(call VerifyXMLCall) (BufferResult, error)
	GetCertFromXML(xml []byte, signID, capacity int) (BufferResult, error)
	GetSigAlgFromXML(xml []byte, capacity int) (BufferResult, error)
}

type driverCMS interface {
	GetTimeFromSig(data []byte, flags, sigID int) (uint64, int64)
	GetCertFromCMS(call GetCertFromCMSCall) (BufferResult, error)
}

type driverNetwork interface {
	SetTSAURL(tsaURL string) uint64
	SetProxy(call ProxyCall) uint64
}

type driverZIP interface {
	ZipConVerify(zipFile string, flags, capacity int) (BufferResult, error)
	ZipConSign(call ZipConSignCall) uint64
	GetCertFromZipFile(call GetCertFromZipFileCall) (BufferResult, error)
}

// Context is a low-level handle to KalkanCrypt.
//
// Context has the same method set on every platform. Builds with a native
// driver delegate to the loaded KalkanCrypt library. Builds without a native
// driver return ErrUnavailable from Open, so callers normally never receive a
// Context value. A closed Context reports ErrClosed for methods that can return
// errors and KCR_LIBRARYNOTINITIALIZED for status-code-only methods.
type Context struct {
	driver driver
}

// Available reports whether the current build has a native KalkanCrypt loader.
func Available() bool { return driverAvailable }

// Open loads a KalkanCrypt dynamic library. Builds without a native loader
// return ErrUnavailable.
func Open(library string) (*Context, error) {
	if err := checkNativeString(library); err != nil {
		return nil, err
	}

	d, err := openDriver(library)
	if err != nil {
		return nil, err
	}

	return &Context{driver: d}, nil
}

func (c *Context) closed() bool { return c == nil || c.driver == nil }

// Close releases the low-level library handle. It may be called more than once.
func (c *Context) Close() error {
	if c.closed() {
		return nil
	}

	d := c.driver
	c.driver = nil

	return d.Close()
}

// ClearError clears KalkanCrypt's process-global last-error state when the
// loaded library exports KC_InternalClearError. Older libraries may not provide
// that optional symbol.
func (c *Context) ClearError() {
	if c.closed() {
		return
	}

	c.driver.ClearError()
}
