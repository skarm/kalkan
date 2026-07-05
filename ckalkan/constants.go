package ckalkan

// Store is a KalkanCrypt key storage/provider type (KCST_*).
type Store uint64

const (
	// StorePKCS12 selects a file-system PKCS#12 container.
	StorePKCS12 Store = 0x00000001
	// StoreKZIDCard selects a Kazakhstan ID card storage provider.
	StoreKZIDCard Store = 0x00000002
	// StoreKazToken selects a KazToken storage provider.
	StoreKazToken Store = 0x00000004
	// StoreEToken72K selects an eToken 72K storage provider.
	StoreEToken72K Store = 0x00000008
	// StoreJaCarta selects a JaCarta storage provider.
	StoreJaCarta Store = 0x00000010
	// StoreX509Cert selects an X.509 certificate-only storage provider.
	StoreX509Cert Store = 0x00000020
	// StoreAKey selects an aKey storage provider.
	StoreAKey Store = 0x00000040
	// StoreEToken5110 selects an eToken 5110 storage provider.
	StoreEToken5110 Store = 0x00000080
)

// CertFormat is a certificate import/export format (KC_CERT_DER/PEM/B64).
type CertFormat int

const (
	// CertDER imports or exports a certificate in DER binary form.
	CertDER CertFormat = 0x00000101
	// CertPEM imports or exports a certificate in PEM text form.
	CertPEM CertFormat = 0x00000102
	// CertB64 imports or exports a certificate as base64 text.
	CertB64 CertFormat = 0x00000104
)

// CertType is a certificate role in the KalkanCrypt store.
type CertType int

const (
	// CertCA marks a trusted root CA certificate.
	CertCA CertType = 0x00000201
	// CertIntermediate marks an intermediate CA certificate.
	CertIntermediate CertType = 0x00000202
	// CertUser marks an end-user certificate.
	CertUser CertType = 0x00000204
)

// ValidationType is a certificate validation strategy.
type ValidationType int

const (
	// UseNothing disables external CRL/OCSP validation in X509ValidateCertificate.
	UseNothing ValidationType = 0x00000401
	// UseCRL validates a certificate against a CRL path.
	UseCRL ValidationType = 0x00000402
	// UseOCSP validates a certificate through an OCSP responder.
	UseOCSP ValidationType = 0x00000404
)

// Flag is a bit mask accepted by KalkanCrypt functions (KC_* flags).
type Flag int

const (
	// SignDraft requests KalkanCrypt's raw/draft signature format.
	SignDraft Flag = 0x00000001
	// SignCMS requests CMS signature format.
	SignCMS Flag = 0x00000002
	// InPEM marks the primary input as PEM text.
	InPEM Flag = 0x00000004
	// InDER marks the primary input as DER binary data.
	InDER Flag = 0x00000008
	// InBase64 marks the primary input as base64 text.
	InBase64 Flag = 0x00000010
	// In2Base64 marks the secondary input as base64 text.
	In2Base64 Flag = 0x00000020
	// DetachedData requests or verifies a detached signature.
	DetachedData Flag = 0x00000040
	// WithCert asks KalkanCrypt to include the signing certificate.
	WithCert Flag = 0x00000080
	// WithTimestamp asks KalkanCrypt to include a TSA timestamp token.
	WithTimestamp Flag = 0x00000100
	// OutPEM requests PEM text output.
	OutPEM Flag = 0x00000200
	// OutDER requests DER binary output.
	OutDER Flag = 0x00000400
	// OutBase64 requests base64 text output.
	OutBase64 Flag = 0x00000800
	// ProxyOff disables and clears KalkanCrypt proxy settings.
	ProxyOff Flag = 0x00001000
	// ProxyOn enables KalkanCrypt proxy settings.
	ProxyOn Flag = 0x00002000
	// ProxyAuth marks proxy settings as requiring username/password auth.
	ProxyAuth Flag = 0x00004000
	// InFile marks input parameters as file paths instead of in-memory data.
	InFile Flag = 0x00008000
	// NoCheckCertTime skips certificate validity-time checks.
	NoCheckCertTime Flag = 0x00010000
	// HashSHA256 selects SHA-256 hashing where the native function accepts
	// hash flags instead of textual algorithm names.
	HashSHA256 Flag = 0x00020000
	// HashGOST95 selects GOST R 34.11-95 hashing where the native function
	// accepts hash flags instead of textual algorithm names.
	HashGOST95 Flag = 0x00040000
	// GetOCSPResponse asks X509ValidateCertificate to return the OCSP response.
	GetOCSPResponse Flag = 0x00080000
	// HashGOST2015_256 selects the GOST 34.11-2015 256-bit hash variant in
	// SDK versions that expose the flag.
	HashGOST2015_256 Flag = 0x00100000
	// HashGOST2015_512 selects the GOST 34.11-2015 512-bit hash variant in
	// SDK versions that expose the flag.
	HashGOST2015_512 Flag = 0x00200000
)

// XML canonicalization flags.
const (
	// XMLInclC14N selects inclusive XML canonicalization.
	XMLInclC14N Flag = 0x01000001
	// XMLInclC14NComment selects inclusive XML canonicalization with comments.
	XMLInclC14NComment Flag = 0x01000002
	// XMLInclC14N11 selects inclusive XML canonicalization 1.1.
	XMLInclC14N11 Flag = 0x01000004
	// XMLInclC14N11Comment selects inclusive XML canonicalization 1.1 with
	// comments.
	XMLInclC14N11Comment Flag = 0x01000008
	// XMLExclC14N selects exclusive XML canonicalization.
	XMLExclC14N Flag = 0x01000010
	// XMLExclC14NComment selects exclusive XML canonicalization with comments.
	XMLExclC14NComment Flag = 0x01000020

	// XMLCInclC14N selects canonicalization for KalkanCrypt XML-C mode.
	XMLCInclC14N Flag = 0x01000040
	// XMLCInclC14NComment selects XML-C inclusive canonicalization with comments.
	XMLCInclC14NComment Flag = 0x01000080
	// XMLCInclC14N11 selects XML-C inclusive canonicalization 1.1.
	XMLCInclC14N11 Flag = 0x01000100
	// XMLCInclC14N11Comment selects XML-C inclusive canonicalization 1.1 with
	// comments.
	XMLCInclC14N11Comment Flag = 0x01000200
	// XMLCExclC14N selects XML-C exclusive canonicalization.
	XMLCExclC14N Flag = 0x01000400
	// XMLCExclC14NComment selects XML-C exclusive canonicalization with comments.
	XMLCExclC14NComment Flag = 0x01000800
)

// CertProp identifies a field/extension requested from a certificate.
type CertProp int

const (
	// CertPropIssuerCountryName returns the issuer country field.
	CertPropIssuerCountryName CertProp = 0x00000801
	// CertPropIssuerSOPN returns the issuer state or province field.
	CertPropIssuerSOPN CertProp = 0x00000802
	// CertPropIssuerLocalityName returns the issuer locality field.
	CertPropIssuerLocalityName CertProp = 0x00000803
	// CertPropIssuerOrgName returns the issuer organization field.
	CertPropIssuerOrgName CertProp = 0x00000804
	// CertPropIssuerOrgUnitName returns the issuer organizational unit field.
	CertPropIssuerOrgUnitName CertProp = 0x00000805
	// CertPropIssuerCommonName returns the issuer common name.
	CertPropIssuerCommonName CertProp = 0x00000806
	// CertPropSubjectCountryName returns the subject country field.
	CertPropSubjectCountryName CertProp = 0x00000807
	// CertPropSubjectSOPN returns the subject state or province field.
	CertPropSubjectSOPN CertProp = 0x00000808
	// CertPropSubjectLocalityName returns the subject locality field.
	CertPropSubjectLocalityName CertProp = 0x00000809
	// CertPropSubjectCommonName returns the subject common name.
	CertPropSubjectCommonName CertProp = 0x0000080a
	// CertPropSubjectGivenName returns the subject given name.
	CertPropSubjectGivenName CertProp = 0x0000080b
	// CertPropSubjectSurname returns the subject surname.
	CertPropSubjectSurname CertProp = 0x0000080c
	// CertPropSubjectSerialNumber returns the subject serial number.
	CertPropSubjectSerialNumber CertProp = 0x0000080d
	// CertPropSubjectEmail returns the subject email field.
	CertPropSubjectEmail CertProp = 0x0000080e
	// CertPropSubjectOrgName returns the subject organization field.
	CertPropSubjectOrgName CertProp = 0x0000080f
	// CertPropSubjectOrgUnitName returns the subject organizational unit field.
	CertPropSubjectOrgUnitName CertProp = 0x00000810
	// CertPropSubjectBC returns the subject business category field.
	CertPropSubjectBC CertProp = 0x00000811
	// CertPropSubjectDC returns the subject domain component field.
	CertPropSubjectDC CertProp = 0x00000812
	// CertPropNotBefore returns the certificate validity start time.
	CertPropNotBefore CertProp = 0x00000813
	// CertPropNotAfter returns the certificate validity end time.
	CertPropNotAfter CertProp = 0x00000814
	// CertPropKeyUsage returns the key usage extension.
	CertPropKeyUsage CertProp = 0x00000815
	// CertPropExtKeyUsage returns the extended key usage extension.
	CertPropExtKeyUsage CertProp = 0x00000816
	// CertPropAuthKeyID returns the authority key identifier.
	CertPropAuthKeyID CertProp = 0x00000817
	// CertPropSubjKeyID returns the subject key identifier.
	CertPropSubjKeyID CertProp = 0x00000818
	// CertPropCertSN returns the certificate serial number.
	CertPropCertSN CertProp = 0x00000819
	// CertPropIssuerDN returns the issuer distinguished name.
	CertPropIssuerDN CertProp = 0x0000081a
	// CertPropSubjectDN returns the subject distinguished name.
	CertPropSubjectDN CertProp = 0x0000081b
	// CertPropSignatureAlg returns the certificate signature algorithm.
	CertPropSignatureAlg CertProp = 0x0000081c
	// CertPropPubKey returns the public key.
	CertPropPubKey CertProp = 0x0000081d
	// CertPropPoliciesID returns certificate policy identifiers.
	CertPropPoliciesID CertProp = 0x0000081e
	// CertPropOCSP returns the OCSP responder URL when supported by the SDK.
	CertPropOCSP CertProp = 0x0000081f
	// CertPropGetCRL returns the CRL distribution point URL when supported by the SDK.
	CertPropGetCRL CertProp = 0x00000820
	// CertPropGetDeltaCRL returns the delta CRL URL when supported by the SDK.
	CertPropGetDeltaCRL CertProp = 0x00000821
)

// HashAlgorithm is the textual algorithm identifier accepted by HashData.
type HashAlgorithm string

const (
	// SHA256 is the textual SHA-256 algorithm name accepted by HashData.
	SHA256 HashAlgorithm = "sha256"
	// GOST95 is the textual GOST R 34.11-95 algorithm name accepted by HashData.
	GOST95 HashAlgorithm = "Gost34311_95"
	// GOST2015_256 is the textual GOST R 34.11-2015 256-bit algorithm name
	// accepted by HashData in SDK versions that expose the 2015 hash variants.
	GOST2015_256 HashAlgorithm = "GostR3411_2015_256"
	// GOST2015_512 is the textual GOST R 34.11-2015 512-bit algorithm name
	// accepted by HashData in SDK versions that expose the 2015 hash variants.
	GOST2015_512 HashAlgorithm = "GostR3411_2015_512"
)
