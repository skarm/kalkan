package kalkancrypt

import "errors"

var (
	// ErrClosed is returned when a low-level context is used after Close.
	ErrClosed = errors.New("kalkancrypt: context is closed")

	// ErrUnavailable is returned when this binary has no native KalkanCrypt
	// loader for the current platform/build mode.
	ErrUnavailable = errors.New("kalkancrypt: native KalkanCrypt loader is unavailable for this build")
)

// errorLibraryNotInitialized mirrors KCR_LIBRARYNOTINITIALIZED. It is kept here
// instead of importing C constants so that the common Go code builds everywhere.
const errorLibraryNotInitialized uint64 = 0x08f00101

// BufferResult describes one native call attempt that writes to an output
// buffer owned by the low-level layer.
type BufferResult struct {
	Code   uint64
	Data   []byte
	OutLen int
}

// ListResult describes one KC_GetTokens/KC_GetCertificatesList call attempt.
type ListResult struct {
	Code  uint64
	Data  string
	Count uint64
}

// ValidateCertificateCall contains the raw parameters for
// X509ValidateCertificate. Buffer capacities are explicit because the public
// layer owns retry/growth policy.
type ValidateCertificateCall struct {
	Certificate    []byte
	ValidationType int
	ValidationPath string
	CheckTimeUnix  int64
	Flags          int
	InfoCapacity   int
	OCSPCapacity   int
}

// ValidateResult contains the native outputs of X509ValidateCertificate.
type ValidateResult struct {
	Code    uint64
	Info    []byte
	InfoLen int
	OCSP    []byte
	OCSPLen int
}

// VerifyDataCall contains the raw parameters shared by VerifyData and
// UVerifyData.
type VerifyDataCall struct {
	Alias        string
	Flags        int
	Data         []byte
	Signature    []byte
	CertID       int
	DataCapacity int
	InfoCapacity int
	CertCapacity int
}

// VerifyResult contains the native outputs of VerifyData/UVerifyData.
type VerifyResult struct {
	Code    uint64
	Data    []byte
	DataLen int
	Info    []byte
	InfoLen int
	Cert    []byte
	CertLen int
}

// SignXMLCall contains the raw parameters for SignXML.
type SignXMLCall struct {
	Alias           string
	Flags           int
	XML             []byte
	SignNodeID      string
	ParentSignNode  string
	ParentNamespace string
	Capacity        int
}

// SignWSSECall contains the raw parameters for SignWSSE.
type SignWSSECall struct {
	Alias      string
	Flags      uint64
	XML        []byte
	SignNodeID string
	Capacity   int
}

// ProxyCall contains the raw parameters for KC_SetProxy.
type ProxyCall struct {
	Flags    int
	Address  string
	Port     string
	User     string
	Password string
}

// ZipConSignCall contains the raw parameters for ZipConSign.
type ZipConSignCall struct {
	Alias    string
	FilePath string
	Name     string
	OutDir   string
	Flags    int
}
