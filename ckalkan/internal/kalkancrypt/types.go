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

// OutputBufferFunc performs one capacity-aware native output-buffer attempt.
type OutputBufferFunc func(capacity int) (BufferResult, error)

// ListBufferFunc performs one native list-buffer attempt.
type ListBufferFunc func(bufferSize int) (ListResult, error)

// BufferResult describes one native call attempt that writes to an output
// buffer owned by the low-level layer.
type BufferResult struct {
	// Code is the status code returned by the native call.
	Code uint64
	// Data is the native output prefix bounded to the reported length. Its length
	// and capacity never exceed the supplied output buffer capacity.
	Data []byte
	// OutLen is the output length reported by the native call.
	OutLen int
}

// ListResult describes one KC_GetTokens/KC_GetCertificatesList call attempt.
type ListResult struct {
	// Code is the status code returned by the native call.
	Code uint64
	// Data contains the native C-string list up to its first NUL terminator.
	Data string
	// Count is the number of items reported by the native call.
	Count uint64
}

// HashDataCall contains the raw parameters for HashData.
type HashDataCall struct {
	// Algorithm is the hash algorithm name passed to the native function.
	Algorithm string
	// Flags is the native KalkanCrypt hashing flag mask.
	Flags int
	// Data contains the input bytes to hash.
	Data []byte
	// Capacity is the supplied digest output capacity.
	Capacity int
}

// SignHashCall contains the raw parameters for SignHash.
type SignHashCall struct {
	// Alias identifies the key used by the native signer.
	Alias string
	// Flags is the native KalkanCrypt signing flag mask.
	Flags int
	// Hash contains the digest to sign.
	Hash []byte
	// Capacity is the supplied signature output capacity.
	Capacity int
}

// SignDataCall contains the raw parameters for SignData.
type SignDataCall struct {
	// Alias identifies the key used by the native signer.
	Alias string
	// Flags is the native KalkanCrypt signing flag mask.
	Flags int
	// Data contains the input bytes to sign.
	Data []byte
	// Signature contains an existing signature when the selected mode appends to it.
	Signature []byte
	// Capacity is the supplied signature output capacity.
	Capacity int
}

// VerifyXMLCall contains the raw parameters for VerifyXML.
type VerifyXMLCall struct {
	// Alias is passed to the native XML verifier as its key/certificate alias.
	Alias string
	// Flags is the native KalkanCrypt verification flag mask.
	Flags int
	// XML contains the XML document to verify.
	XML []byte
	// Capacity is the supplied verification-info output capacity.
	Capacity int
}

// GetCertFromCMSCall contains the raw parameters for KC_GetCertFromCMS.
type GetCertFromCMSCall struct {
	// CMS contains the CMS data passed to the native function.
	CMS []byte
	// SignID selects a signer certificate from multi-signer data.
	SignID int
	// Flags is the native KalkanCrypt flag mask.
	Flags int
	// Capacity is the supplied certificate output capacity.
	Capacity int
}

// GetCertFromZipFileCall contains the raw parameters for KC_getCertFromZipFile.
type GetCertFromZipFileCall struct {
	// ZipFile is the ZIP container path passed to the native function.
	ZipFile string
	// Flags is the native KalkanCrypt flag mask.
	Flags int
	// SignID selects a signer certificate from multi-signer data.
	SignID int
	// Capacity is the supplied certificate output capacity.
	Capacity int
}

// ValidateCertificateCall contains the raw parameters for
// X509ValidateCertificate. Buffer capacities are explicit because the public
// layer owns retry/growth policy.
type ValidateCertificateCall struct {
	// Certificate contains the certificate passed to the native validator.
	Certificate []byte
	// ValidationType selects the native certificate-validation mode.
	ValidationType int
	// ValidationPath is the path or address used by the selected validation mode.
	ValidationPath string
	// CheckTimeUnix is the validation time represented as a Unix timestamp.
	CheckTimeUnix int64
	// Flags is the native KalkanCrypt validation flag mask.
	Flags int
	// InfoCapacity is the supplied validation-info output capacity.
	InfoCapacity int
	// OCSPCapacity is the supplied OCSP-response output capacity.
	OCSPCapacity int
}

// ValidateResult contains the native outputs of X509ValidateCertificate.
type ValidateResult struct {
	// Code is the status code returned by the native call.
	Code uint64
	// Info contains the reported prefix of the validation-info output buffer.
	Info []byte
	// InfoLen is the validation-info length reported by the native call.
	InfoLen int
	// OCSP contains the reported prefix of the OCSP-response output buffer.
	OCSP []byte
	// OCSPLen is the OCSP-response length reported by the native call.
	OCSPLen int
}

// VerifyDataCall contains the raw parameters shared by VerifyData and the
// internal UVerifyData ABI call.
type VerifyDataCall struct {
	// Alias is passed to the native verifier as its key/certificate alias.
	Alias string
	// Flags is the native KalkanCrypt verification flag mask.
	Flags int
	// Data contains the input data used by the selected verification mode.
	Data []byte
	// Signature contains signature bytes for VerifyData. In the verified Linux
	// SDK, UVerifyData interprets it as a native file path and reads the
	// signature/container from that file.
	Signature []byte
	// CertID selects a signer certificate in multi-signer input.
	CertID int
	// DataCapacity is the supplied decoded-data output capacity.
	DataCapacity int
	// InfoCapacity is the supplied verification-info output capacity.
	InfoCapacity int
	// CertCapacity is the supplied signer-certificate output capacity.
	CertCapacity int
}

// VerifyResult contains the native outputs of VerifyData/UVerifyData.
type VerifyResult struct {
	// Code is the status code returned by the native call.
	Code uint64
	// Data contains the reported prefix of the decoded-data output buffer.
	Data []byte
	// DataLen is the decoded-data length reported by the native call.
	DataLen int
	// Info contains the reported prefix of the verification-info output buffer.
	Info []byte
	// InfoLen is the verification-info length reported by the native call.
	InfoLen int
	// Cert contains the reported prefix of the signer-certificate output buffer.
	Cert []byte
	// CertLen is the signer-certificate length reported by the native call.
	CertLen int
}

// SignXMLCall contains the raw parameters for SignXML.
type SignXMLCall struct {
	// Alias identifies the key used by the native signer.
	Alias string
	// Flags is the native KalkanCrypt signing flag mask.
	Flags int
	// XML contains the XML document to sign.
	XML []byte
	// SignNodeID is the XML node ID passed to the native signer.
	SignNodeID string
	// ParentSignNode is the parent signature node name passed to the native signer.
	ParentSignNode string
	// ParentNamespace is the parent signature namespace passed to the native signer.
	ParentNamespace string
	// Capacity is the supplied signed-XML output capacity.
	Capacity int
}

// SignWSSECall contains the raw parameters for SignWSSE.
type SignWSSECall struct {
	// Alias identifies the key used by the native signer.
	Alias string
	// Flags is the native KalkanCrypt signing flag mask.
	Flags uint64
	// XML contains the XML document to sign.
	XML []byte
	// SignNodeID is the XML node ID passed to the native signer.
	SignNodeID string
	// Capacity is the supplied signed-XML output capacity.
	Capacity int
}

// ProxyCall contains the raw parameters for KC_SetProxy.
type ProxyCall struct {
	// Flags is the native KalkanCrypt proxy flag mask.
	Flags int
	// Address is the proxy host passed to the native library.
	Address string
	// Port is the proxy port passed to the native library.
	Port string
	// User is the optional proxy user name.
	User string
	// Password is the optional proxy password.
	Password string
}

// ZipConSignCall contains the raw parameters for ZipConSign.
type ZipConSignCall struct {
	// Alias identifies the key used by the native signer.
	Alias string
	// FilePath is the path of the file added to the signed container.
	FilePath string
	// Name is the name assigned to the generated container.
	Name string
	// OutDir is the directory where the generated container is written.
	OutDir string
	// Flags is the native KalkanCrypt signing flag mask.
	Flags int
}
