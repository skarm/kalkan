package ckalkan

// ListResult is returned by KC_GetTokens and KC_GetCertificatesList.
type ListResult struct {
	// Data is the raw list string returned by KalkanCrypt.
	Data string
	// Count is the native item count returned alongside Data.
	Count uint64
}

// ValidateCertificateRequest maps to X509ValidateCertificate parameters.
type ValidateCertificateRequest struct {
	// Certificate contains the certificate bytes to validate.
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

// ValidateCertificateResult is returned by X509ValidateCertificate.
type ValidateCertificateResult struct {
	// Info is the native validation information string.
	Info string
	// OCSPResponse is the optional raw OCSP response returned by KalkanCrypt.
	OCSPResponse []byte
}

// SignDataRequest maps to SignData parameters.
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

// SignXMLRequest maps to SignXML parameters.
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

// VerifyDataRequest maps to VerifyData parameters.
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

// VerifyDataResult is returned by VerifyData.
type VerifyDataResult struct {
	// Data contains decoded data returned by KalkanCrypt.
	Data []byte
	// VerifyInfo is the native verification information string.
	VerifyInfo string
	// Cert contains the optional signer certificate returned by KalkanCrypt.
	Cert []byte
}

// SignWSSERequest maps to SignWSSE parameters.
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

// ProxyRequest maps to KC_SetProxy parameters.
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

// ZipConSignRequest maps to ZipConSign parameters.
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
