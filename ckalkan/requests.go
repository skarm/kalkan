package ckalkan

// ListResult contains a native token or certificate list and its item count.
type ListResult struct {
	// Data is the raw list string returned by KalkanCrypt.
	Data string
	// Count is the native item count returned alongside Data.
	Count uint64
}

// ValidateCertificateRequest specifies the certificate, revocation source,
// validation time, and output capacities for [Client.X509ValidateCertificate].
type ValidateCertificateRequest struct {
	// Certificate contains the certificate bytes to validate. With InFile it
	// contains the path to the certificate file.
	Certificate []byte
	// ValidationType selects CRL, OCSP, or no external validation.
	ValidationType ValidationType
	// ValidationPath is passed to KalkanCrypt. With UseOCSP it specifies the
	// responder URL.
	ValidationPath string
	// CheckTimeUnix is the validation time as a Unix timestamp. Zero lets
	// KalkanCrypt use its own default behavior.
	CheckTimeUnix int64
	// Flags contains additional KalkanCrypt validation flags.
	Flags Flag
	// OutputCapacity overrides the first validation-info output buffer size.
	OutputCapacity int
	// OCSPCapacity overrides the first OCSP-response output buffer size.
	OCSPCapacity int
}

// ValidateCertificateResult contains native validation diagnostics and an
// optional OCSP response from [Client.X509ValidateCertificate].
type ValidateCertificateResult struct {
	// Info is the native validation information string.
	Info string
	// OCSPResponse is the raw OCSP response returned by KalkanCrypt when
	// GetOCSPResponse is set. Otherwise it is nil.
	OCSPResponse []byte
}

// SignDataRequest specifies the primary data, optional existing signature,
// and native flags for [Client.SignData].
type SignDataRequest struct {
	// Alias identifies the loaded key alias used for signing.
	Alias string
	// Flags contains SignData/KalkanCrypt flags.
	Flags Flag
	// Data contains the input bytes to sign. With InFile it contains the path to
	// the primary input file.
	Data []byte
	// Signature contains an existing in-memory signature when the selected mode
	// appends to it. In2Base64 marks this secondary input as Base64 text.
	Signature []byte
	// OutputCapacity overrides the estimated first signature output buffer size.
	OutputCapacity int
}

// SignXMLRequest specifies the document, signature placement, and output
// capacity for [Client.SignXML].
type SignXMLRequest struct {
	// Alias identifies the loaded key alias used for signing.
	Alias string
	// Flags contains SignXML/KalkanCrypt flags.
	Flags Flag
	// XML contains the input XML document.
	XML []byte
	// SignNodeID is the XML node id passed to KalkanCrypt.
	SignNodeID string
	// ParentSignNode is the parent signature node name passed to KalkanCrypt.
	ParentSignNode string
	// ParentNamespace is the parent signature namespace passed to KalkanCrypt.
	ParentNamespace string
	// OutputCapacity overrides the first signed-XML output buffer size.
	OutputCapacity int
}

// VerifyDataRequest specifies signature verification inputs and capacities
// for the decoded data, diagnostic, and certificate outputs of [Client.VerifyData].
type VerifyDataRequest struct {
	// Alias is the key/certificate alias parameter accepted by KalkanCrypt.
	Alias string
	// Flags contains VerifyData/KalkanCrypt flags.
	Flags Flag
	// Data contains the signed or detached input data, depending on Flags.
	Data []byte
	// Signature contains the CMS/signature bytes. With InFile it contains the
	// path to the signature file.
	Signature []byte
	// CertID selects a signer certificate from multi-signer data.
	CertID int
	// DataCapacity overrides the first native data output buffer size. Decoded
	// data is returned only for an attached CMS passed in memory. On Linux the
	// value is ignored for detached, draft, and InFile verification; unverified
	// platforms retain the native buffer for ABI compatibility.
	DataCapacity int
	// VerifyInfoCapacity overrides the first verification-info output buffer size.
	VerifyInfoCapacity int
	// CertCapacity overrides the first signer-certificate output buffer size.
	CertCapacity int
}

// VerifyDataResult contains the native outputs of [Client.VerifyData]:
// decoded content when available, verification diagnostics, and a signer certificate.
type VerifyDataResult struct {
	// Data contains decoded data returned by KalkanCrypt.
	Data []byte
	// VerifyInfo is the native verification information string.
	VerifyInfo string
	// Cert contains the optional signer certificate returned by KalkanCrypt.
	Cert []byte
}

// SignWSSERequest specifies the XML document and node to sign with
// [Client.SignWSSE].
type SignWSSERequest struct {
	// Alias identifies the loaded key alias used for signing.
	Alias string
	// Flags contains SignWSSE/KalkanCrypt flags.
	Flags Flag
	// XML contains the input XML document.
	XML []byte
	// SignNodeID is the XML node id passed to KalkanCrypt.
	SignNodeID string
	// OutputCapacity overrides the first output buffer size.
	OutputCapacity int
}

// ProxyRequest specifies the native proxy mode and connection parameters for
// [Client.SetProxy].
type ProxyRequest struct {
	// Flags contains proxy-related KalkanCrypt flags such as ProxyOn or ProxyAuth.
	Flags Flag
	// Address is the proxy host or IP address.
	Address string
	// Port is the proxy port as expected by KalkanCrypt.
	Port string
	// User is the optional proxy username.
	User string
	// Password is the optional proxy password.
	Password string
}

// ZipConSignRequest specifies the file, container name, output directory, and
// signing flags for [Client.ZipConSign].
type ZipConSignRequest struct {
	// Alias identifies the loaded key alias used for signing.
	Alias string
	// FilePath is the input file path passed to KalkanCrypt.
	FilePath string
	// Name is the output ZIP container name.
	Name string
	// OutDir is the output directory for the ZIP container.
	OutDir string
	// Flags contains ZipConSign/KalkanCrypt flags.
	Flags Flag
}
