package kalkan

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/internal/nativebytes"
)

const maxExtractedSignerCertificates = 64

const (
	certificatePEMHeader    = "-----BEGIN CERTIFICATE-----\n"
	certificatePEMFooter    = "-----END CERTIFICATE-----\n"
	certificatePEMLineWidth = 64
)

// CertificateInfo contains selected KalkanCrypt certificate properties.
// Unrequested or unavailable properties have zero values. Parsed fields and
// inferred subject details depend on the properties selected by
// [Client.X509CertificateGetInfoFields].
type CertificateInfo struct {
	// Subject is the subject distinguished name.
	Subject string
	// SerialNumber is the certificate serial number.
	SerialNumber string
	// ValidFrom is the parsed notBefore value.
	ValidFrom time.Time
	// ValidUntil is the parsed notAfter value.
	ValidUntil time.Time
	// Issuer is the issuer distinguished name.
	Issuer string
	// Policy is the certificate policies string.
	Policy string
	// KeyUsage is the key usage string.
	KeyUsage string
	// ExtKeyUsage is the extended key usage string.
	ExtKeyUsage string
	// AuthKeyID is the authority key identifier.
	AuthKeyID string
	// SubjKeyID is the subject key identifier.
	SubjKeyID string
	// SignatureAlgorithm describes the certificate signature algorithm as
	// "signatureAlgorithm=<name>(<OID>)". The Java backend uses native SDK names
	// for known algorithms and returns the OID alone for unknown algorithms.
	SignatureAlgorithm string
	// PublicKey is the public key string.
	PublicKey string
	// OCSPURL is the OCSP responder string.
	OCSPURL string
	// CRLURL is the CRL distribution point string.
	CRLURL string
	// DeltaCRLURL is the delta CRL distribution point string.
	DeltaCRLURL string
	// SubjectCountry is the subject country value.
	SubjectCountry string
	// SubjectSerialNumber is the subject serialNumber value.
	SubjectSerialNumber string
	// SubjectOrganization is the subject organization value.
	SubjectOrganization string
	// SubjectOrganizationalUnit is the subject organizational unit value.
	SubjectOrganizationalUnit string
	// Policies contains parsed values from Policy.
	Policies []string
	// KeyUsages contains parsed values from KeyUsage.
	KeyUsages []string
	// ExtKeyUsages contains parsed values from ExtKeyUsage.
	ExtKeyUsages []string
	// IIN is parsed from Kazakhstan subject serialNumber values prefixed with "IIN".
	IIN string
	// BIN is parsed from Kazakhstan subject OU values prefixed with "BIN".
	BIN string
	// SubjectType is inferred from known Kazakhstan NCA policy OIDs or IIN/BIN.
	SubjectType CertificateSubjectType
	// Roles contains recognized Kazakhstan NCA role policy OIDs.
	Roles []CertificateRole
}

// CertificateSubjectType identifies known Kazakhstan NCA subject type policy OIDs.
type CertificateSubjectType string

const (
	// CertificateSubjectUnknown means the subject type could not be inferred.
	CertificateSubjectUnknown CertificateSubjectType = ""
	// CertificateSubjectPerson identifies policy OID 1.2.398.3.3.4.1.1.
	CertificateSubjectPerson CertificateSubjectType = kzPolicyPerson
	// CertificateSubjectLegalEntity identifies policy OID 1.2.398.3.3.4.1.2.
	CertificateSubjectLegalEntity CertificateSubjectType = kzPolicyLegalEntity
)

// CertificateRole identifies known Kazakhstan NCA role policy OIDs.
type CertificateRole string

const (
	// CertificateRolePersonSystem identifies policy OID 1.2.398.3.3.4.1.1.1.
	CertificateRolePersonSystem CertificateRole = kzPolicyPersonSystem
	// CertificateRoleFirstHead identifies policy OID 1.2.398.3.3.4.1.2.1.
	CertificateRoleFirstHead CertificateRole = kzPolicyFirstHead
	// CertificateRoleSigner identifies policy OID 1.2.398.3.3.4.1.2.2.
	CertificateRoleSigner CertificateRole = kzPolicySigner
	// CertificateRoleFinancialSigner identifies policy OID 1.2.398.3.3.4.1.2.3.
	CertificateRoleFinancialSigner CertificateRole = kzPolicyFinancialSigner
	// CertificateRoleHR identifies policy OID 1.2.398.3.3.4.1.2.4.
	CertificateRoleHR CertificateRole = kzPolicyHR
	// CertificateRoleEmployee identifies policy OID 1.2.398.3.3.4.1.2.5.
	CertificateRoleEmployee CertificateRole = kzPolicyEmployee
	// CertificateRoleLegalEntitySystem identifies policy OID 1.2.398.3.3.4.1.2.6.
	CertificateRoleLegalEntitySystem CertificateRole = kzPolicyLegalEntitySystem
)

const (
	kzIINPrefix = "IIN"
	kzBINPrefix = "BIN"

	kzPolicyPerson               = "1.2.398.3.3.4.1.1"
	kzPolicyPersonSystem         = "1.2.398.3.3.4.1.1.1"
	kzPolicyLegalEntity          = "1.2.398.3.3.4.1.2"
	kzPolicyFirstHead            = "1.2.398.3.3.4.1.2.1"
	kzPolicySigner               = "1.2.398.3.3.4.1.2.2"
	kzPolicyFinancialSigner      = "1.2.398.3.3.4.1.2.3"
	kzPolicyHR                   = "1.2.398.3.3.4.1.2.4"
	kzPolicyEmployee             = "1.2.398.3.3.4.1.2.5"
	kzPolicyLegalEntitySystem    = "1.2.398.3.3.4.1.2.6"
	kzPolicyLegalEntitySystemPfx = kzPolicyLegalEntitySystem + "."
)

// CertificateInfoField selects certificate properties requested from
// KalkanCrypt. Combine fields with bitwise OR. [Client.X509CertificateGetInfo]
// requests [CertificateInfoAllFields].
type CertificateInfoField uint64

const (
	// CertificateInfoSubject requests the native subject distinguished name.
	CertificateInfoSubject CertificateInfoField = 1 << iota
	// CertificateInfoSerialNumber requests the native serial number.
	CertificateInfoSerialNumber
	// CertificateInfoValidFrom requests the native notBefore value.
	CertificateInfoValidFrom
	// CertificateInfoValidUntil requests the native notAfter value.
	CertificateInfoValidUntil
	// CertificateInfoIssuer requests the native issuer distinguished name.
	CertificateInfoIssuer
	// CertificateInfoPolicy requests native certificate policy values.
	CertificateInfoPolicy
	// CertificateInfoKeyUsage requests native key usage values.
	CertificateInfoKeyUsage
	// CertificateInfoExtKeyUsage requests native extended key usage values.
	CertificateInfoExtKeyUsage
	// CertificateInfoAuthKeyID requests the authority key identifier.
	CertificateInfoAuthKeyID
	// CertificateInfoSubjKeyID requests the subject key identifier.
	CertificateInfoSubjKeyID
	// CertificateInfoSignatureAlgorithm requests the signature algorithm.
	CertificateInfoSignatureAlgorithm
	// CertificateInfoPublicKey requests the native public key string.
	CertificateInfoPublicKey
	// CertificateInfoOCSPURL requests the OCSP responder URL.
	CertificateInfoOCSPURL
	// CertificateInfoCRLURL requests the CRL distribution point URL.
	CertificateInfoCRLURL
	// CertificateInfoDeltaCRLURL requests the delta CRL distribution point URL.
	CertificateInfoDeltaCRLURL
	// CertificateInfoSubjectCountry requests the subject country value.
	CertificateInfoSubjectCountry
	// CertificateInfoSubjectSerialNumber requests the subject serialNumber value.
	CertificateInfoSubjectSerialNumber
	// CertificateInfoSubjectOrganization requests the subject organization value.
	CertificateInfoSubjectOrganization
	// CertificateInfoSubjectOrganizationalUnit requests the subject organizational unit value.
	CertificateInfoSubjectOrganizationalUnit
)

// CertificateInfoAllFields requests the same properties as X509CertificateGetInfo.
const CertificateInfoAllFields = CertificateInfoSubject |
	CertificateInfoSerialNumber |
	CertificateInfoValidFrom |
	CertificateInfoValidUntil |
	CertificateInfoIssuer |
	CertificateInfoPolicy |
	CertificateInfoKeyUsage |
	CertificateInfoExtKeyUsage |
	CertificateInfoAuthKeyID |
	CertificateInfoSubjKeyID |
	CertificateInfoSignatureAlgorithm |
	CertificateInfoPublicKey |
	CertificateInfoOCSPURL |
	CertificateInfoCRLURL |
	CertificateInfoDeltaCRLURL |
	CertificateInfoSubjectCountry |
	CertificateInfoSubjectSerialNumber |
	CertificateInfoSubjectOrganization |
	CertificateInfoSubjectOrganizationalUnit

type certificateInfoProperty struct {
	field    CertificateInfoField
	prop     ckalkan.CertProp
	optional bool
}

//nolint:gochecknoglobals // immutable operation metadata avoids rebuilding closure tables per call.
var certificateInfoProperties = [...]certificateInfoProperty{
	{field: CertificateInfoSubject, prop: ckalkan.CertPropSubjectDN},
	{field: CertificateInfoSerialNumber, prop: ckalkan.CertPropCertSN},
	{field: CertificateInfoValidFrom, prop: ckalkan.CertPropNotBefore},
	{field: CertificateInfoValidUntil, prop: ckalkan.CertPropNotAfter},
	{field: CertificateInfoIssuer, prop: ckalkan.CertPropIssuerDN},
	{field: CertificateInfoPolicy, prop: ckalkan.CertPropPoliciesID},
	{field: CertificateInfoSubjectCountry, prop: ckalkan.CertPropSubjectCountryName, optional: true},
	{field: CertificateInfoSubjectSerialNumber, prop: ckalkan.CertPropSubjectSerialNumber, optional: true},
	{field: CertificateInfoSubjectOrganization, prop: ckalkan.CertPropSubjectOrgName, optional: true},
	{field: CertificateInfoSubjectOrganizationalUnit, prop: ckalkan.CertPropSubjectOrgUnitName, optional: true},
	{field: CertificateInfoKeyUsage, prop: ckalkan.CertPropKeyUsage},
	{field: CertificateInfoExtKeyUsage, prop: ckalkan.CertPropExtKeyUsage},
	{field: CertificateInfoAuthKeyID, prop: ckalkan.CertPropAuthKeyID},
	{field: CertificateInfoSubjKeyID, prop: ckalkan.CertPropSubjKeyID},
	{field: CertificateInfoSignatureAlgorithm, prop: ckalkan.CertPropSignatureAlg},
	{field: CertificateInfoPublicKey, prop: ckalkan.CertPropPubKey},
	{field: CertificateInfoOCSPURL, prop: ckalkan.CertPropOCSP, optional: true},
	{field: CertificateInfoCRLURL, prop: ckalkan.CertPropGetCRL, optional: true},
	{field: CertificateInfoDeltaCRLURL, prop: ckalkan.CertPropGetDeltaCRL, optional: true},
}

// X509ExportCertificateFromStore exports the default certificate from
// the session's key store and parses it as an x509 certificate.
func (c *Client) X509ExportCertificateFromStore(ctx context.Context) (*x509.Certificate, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	out, err := withOperationsResult(c, ctx, "X509ExportCertificateFromStore", func(operations certificateOperations) ([]byte, error) {
		return operations.X509ExportCertificateFromStore("", ckalkan.CertDER)
	})
	if err != nil {
		return nil, err
	}

	cert, err := parseNativeCertificate(out)
	if err != nil {
		return nil, fmt.Errorf("kalkan: parse exported certificate: %w", err)
	}

	return cert, nil
}

// X509CertificateGetInfo returns the properties selected by
// [CertificateInfoAllFields]. It uses the same certificate requirements as
// [Client.X509CertificateGetInfoFields].
func (c *Client) X509CertificateGetInfo(ctx context.Context, cert *x509.Certificate) (*CertificateInfo, error) {
	return c.X509CertificateGetInfoFields(ctx, cert, CertificateInfoAllFields)
}

// X509CertificateGetInfoFields retrieves properties selected by the bitmask
// fields. The mask must be nonzero and contain only [CertificateInfoAllFields]
// bits. cert must be non-nil with nonempty Raw DER; other cert fields are unused.
func (c *Client) X509CertificateGetInfoFields(ctx context.Context, cert *x509.Certificate, fields CertificateInfoField) (*CertificateInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if c == nil {
		return nil, ErrClosed
	}

	if cert == nil {
		return nil, fmt.Errorf("%w: certificate is nil", ErrInvalidInput)
	}

	if len(cert.Raw) == 0 {
		return nil, fmt.Errorf("%w: certificate raw DER is empty", ErrInvalidInput)
	}

	if fields == 0 {
		return nil, fmt.Errorf("%w: certificate info fields are required", ErrInvalidInput)
	}

	if unknown := fields &^ CertificateInfoAllFields; unknown != 0 {
		return nil, fmt.Errorf("%w: unknown certificate info fields %#x", ErrInvalidInput, uint64(unknown))
	}

	if err := validateCertificateInfoInputSize(len(cert.Raw), c.configuredMaxInputSize()); err != nil {
		return nil, err
	}

	certPEM := c.cachedPEMForCertificate(cert.Raw)

	info := &CertificateInfo{}

	for _, item := range certificateInfoProperties {
		if fields&item.field == 0 {
			continue
		}

		var expectedCode ckalkan.ErrorCode
		if item.optional {
			expectedCode = ckalkan.ErrorGetCertProp
		}

		value, err := withOperationsResult(c, ctx, "X509CertificateGetInfo", func(operations certificateOperations) ([]byte, error) {
			if certPEM == nil {
				// Populate only while the open client's gate is held, so Close
				// cannot finish before a queued call publishes a new cache entry.
				certPEM = c.cachedPEMForCertificate(cert.Raw)
				if certPEM == nil {
					certPEM = c.encodeAndCacheCertificatePEM(cert.Raw)
				}
			}

			return operations.X509CertificateGetInfo(certPEM, item.prop)
		}, expectedCode)
		if err != nil {
			if item.optional && isKalkanErrorCode(err, ckalkan.ErrorGetCertProp) {
				continue
			}

			return nil, fmt.Errorf("kalkan: get certificate property %v: %w", item.prop, err)
		}

		if err := applyCertificateInfoProperty(info, item.field, string(nativebytes.BeforeNUL(value))); err != nil {
			return nil, err
		}
	}

	info.applyKazakhstanSubjectDetails()

	return info, nil
}

type pemCacheEntry struct {
	der []byte
	pem []byte
}

// Check both raw and expanded input before encoding or retaining a cache entry.
// The native C int bound also keeps the size arithmetic safe on 32-bit builds.
func validateCertificateInfoInputSize(derSize int, maxSize int64) error {
	limit := int64(math.MaxInt32)
	if maxSize > 0 {
		limit = min(limit, maxSize)
	}

	if err := validateInputSize(int64(derSize), "certificate", limit); err != nil {
		return err
	}

	return validateInputSize(certificatePEMSize(derSize), "certificate", limit)
}

// certificatePEMSize excludes the reserved NUL terminator. Use int64 arithmetic
// so inputs in the native C int range remain safe on 32-bit Go builds.
func certificatePEMSize(derSize int) int64 {
	encoded := (int64(derSize) + 2) / 3 * 4
	lines := (encoded + certificatePEMLineWidth - 1) / certificatePEMLineWidth

	return int64(len(certificatePEMHeader)+len(certificatePEMFooter)) + encoded + lines
}

func (c *Client) cachedPEMForCertificate(der []byte) []byte {
	if cached := c.pemCache.Load(); cached != nil && bytes.Equal(cached.der, der) {
		return cached.pem
	}

	return nil
}

func (c *Client) encodeAndCacheCertificatePEM(der []byte) []byte {
	encoded := encodeCertificatePEM(der)
	c.pemCache.Store(&pemCacheEntry{
		der: slices.Clone(der),
		pem: encoded,
	})

	return encoded
}

// encodeCertificatePEM returns PEM with 64-column Base64 lines and a trailing
// NUL byte outside the logical slice for native C-string consumers.
func encodeCertificatePEM(der []byte) []byte {
	const rawChunkSize = certificatePEMLineWidth / 4 * 3

	logicalLen := certificatePEMSize(len(der))
	out := make([]byte, logicalLen+1)
	offset := copy(out, certificatePEMHeader)

	for len(der) > 0 {
		chunkLen := min(len(der), rawChunkSize)
		chunkEncodedLen := base64.StdEncoding.EncodedLen(chunkLen)
		base64.StdEncoding.Encode(out[offset:offset+chunkEncodedLen], der[:chunkLen])
		offset += chunkEncodedLen
		out[offset] = '\n'
		offset++
		der = der[chunkLen:]
	}

	copy(out[offset:], certificatePEMFooter)

	// Keep a trailing zero outside the logical slice. The Linux native adapter
	// can pass this internal buffer directly to KalkanCrypt without another
	// full PEM copy.
	return out[:logicalLen]
}

func applyCertificateInfoProperty(info *CertificateInfo, field CertificateInfoField, value string) error {
	switch field {
	case CertificateInfoSubject:
		info.Subject = value
	case CertificateInfoSerialNumber:
		info.SerialNumber = value
	case CertificateInfoValidFrom:
		parsed, err := parseNativeCertificateTime("notBefore", value)
		if err != nil {
			return err
		}

		info.ValidFrom = parsed
	case CertificateInfoValidUntil:
		parsed, err := parseNativeCertificateTime("notAfter", value)
		if err != nil {
			return err
		}

		info.ValidUntil = parsed
	case CertificateInfoIssuer:
		info.Issuer = value
	case CertificateInfoPolicy:
		info.Policy = value
		info.Policies = splitNativePropertyValues(value)
	case CertificateInfoSubjectCountry:
		info.SubjectCountry = nativePropertyValue(value)
	case CertificateInfoSubjectSerialNumber:
		info.SubjectSerialNumber = nativePropertyValue(value)
	case CertificateInfoSubjectOrganization:
		info.SubjectOrganization = nativePropertyValue(value)
	case CertificateInfoSubjectOrganizationalUnit:
		info.SubjectOrganizationalUnit = nativePropertyValue(value)
	case CertificateInfoKeyUsage:
		info.KeyUsage = value
		info.KeyUsages = splitNativePropertyValues(value)
	case CertificateInfoExtKeyUsage:
		info.ExtKeyUsage = value
		info.ExtKeyUsages = splitNativePropertyValues(value)
	case CertificateInfoAuthKeyID:
		info.AuthKeyID = value
	case CertificateInfoSubjKeyID:
		info.SubjKeyID = value
	case CertificateInfoSignatureAlgorithm:
		info.SignatureAlgorithm = value
	case CertificateInfoPublicKey:
		info.PublicKey = value
	case CertificateInfoOCSPURL:
		info.OCSPURL = value
	case CertificateInfoCRLURL:
		info.CRLURL = value
	case CertificateInfoDeltaCRLURL:
		info.DeltaCRLURL = value
	}

	return nil
}

// GetCertFromCMS extracts signer certificates embedded in a CMS container.
// File sources are read into memory by Go and obey WithMaxInputSize.
func (c *Client) GetCertFromCMS(ctx context.Context, cms Source) ([]*x509.Certificate, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	value, flags, err := cmsSignatureInput(cms, EncodingDER, c.configuredMaxInputSize())
	if err != nil {
		return nil, err
	}

	flags |= ckalkan.SignCMS | ckalkan.OutBase64

	if cms.file {
		// KC_GetCertFromCMS expects CMS contents even when KC_IN_FILE is set.
		// Read a file once so every signer lookup sees the same container.
		value, err = readCMSInputFile(ctx, string(value), c.configuredMaxInputSize(), false)
		if err != nil {
			return nil, err
		}
	}

	return collectSignerCertificates(ctx, ckalkan.ErrorCertNotFound, func(signID int) ([]byte, error) {
		var expectedCode ckalkan.ErrorCode
		if signID > 0 {
			expectedCode = ckalkan.ErrorCertNotFound
		}

		return withOperationsResult(c, ctx, "GetCertFromCMS", func(operations cmsOperations) ([]byte, error) {
			// KC_GetCertFromCMS numbers certificates from 1. Keep the
			// collection count zero-based so its limit still counts results.
			return operations.GetCertFromCMS(value, signID+1, flags)
		}, expectedCode)
	})
}

// GetTimeFromSig returns the timestamp embedded for CMS signer 0 (the first
// signer). The low-level ckalkan.Client.GetTimeFromSig method accepts a signer
// index.
func (c *Client) GetTimeFromSig(ctx context.Context, signature Source) (time.Time, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}

	value, flags, err := cmsSignatureInput(signature, EncodingDER, c.configuredMaxInputSize())
	if err != nil {
		return time.Time{}, err
	}

	if signature.file {
		flags |= ckalkan.InFile
	}

	return withOperationsResult(c, ctx, "GetTimeFromSig", func(operations cmsOperations) (time.Time, error) {
		return operations.GetTimeFromSig(value, flags, 0)
	})
}

// GetCertFromXML extracts one embedded certificate per XML signature in document
// order. It does not verify signatures or establish trust in the certificates.
func (c *Client) GetCertFromXML(ctx context.Context, source Source) ([]*x509.Certificate, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	value, err := xmlInput(source, c.configuredMaxInputSize())
	if err != nil {
		return nil, err
	}

	value = xmlCertificateInput(value)

	return collectSignerCertificates(ctx, ckalkan.ErrorIDAttrNotFound, func(signID int) ([]byte, error) {
		var expectedCode ckalkan.ErrorCode
		if signID > 0 {
			expectedCode = ckalkan.ErrorIDAttrNotFound
		}

		return withOperationsResult(c, ctx, "GetCertFromXML", func(operations xmlOperations) ([]byte, error) {
			return operations.GetCertFromXML(value, signID+1)
		}, expectedCode)
	})
}

// GetSigAlgFromXML returns the native XML signature algorithm identifier.
func (c *Client) GetSigAlgFromXML(ctx context.Context, source Source) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	value, err := xmlInput(source, c.configuredMaxInputSize())
	if err != nil {
		return "", err
	}

	return withOperationsResult(c, ctx, "GetSigAlgFromXML", func(operations xmlOperations) (string, error) {
		return operations.GetSigAlgFromXML(value)
	})
}

func collectSignerCertificates(ctx context.Context, endCode ckalkan.ErrorCode, fetch func(signID int) ([]byte, error)) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for signID := 0; ; signID++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		out, err := fetch(signID)
		if err != nil {
			if isKalkanErrorCode(err, endCode) {
				if len(certs) == 0 {
					return nil, err
				}

				return certs, nil
			}

			return nil, err
		}

		if isEmptyNativeCertificate(out) {
			if len(certs) == 0 {
				return nil, fmt.Errorf("%w: signer certificate output is empty", ErrInvalidInput)
			}

			return certs, nil
		}

		// The extra lookup at the limit distinguishes exactly the supported
		// number of certificates from a truncated result.
		if signID == maxExtractedSignerCertificates {
			return nil, fmt.Errorf("%w: signer certificate count exceeds %d", ErrInvalidInput, maxExtractedSignerCertificates)
		}

		cert, err := parseNativeCertificate(out)
		if err != nil {
			return nil, fmt.Errorf("kalkan: parse signer certificate %d: %w", signID, err)
		}

		certs = append(certs, cert)
	}
}

// parseNativeCertificate accepts DER, a single CERTIFICATE PEM block, or
// Base64 DER from a native result. It permits NUL padding without truncating
// embedded zero bytes in binary DER.
func parseNativeCertificate(data []byte) (*x509.Certificate, error) {
	if isEmptyNativeCertificate(data) {
		return nil, fmt.Errorf("%w: certificate output is empty", ErrInvalidInput)
	}

	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert, nil
	}

	// Binary native buffers may be NUL-padded. Use the outer ASN.1 length to
	// separate padding without truncating legitimate NUL bytes inside DER.
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(data, &raw); err == nil && len(rest) != 0 && len(bytes.Trim(rest, "\x00")) == 0 {
		if cert, err := x509.ParseCertificate(raw.FullBytes); err == nil {
			return cert, nil
		}
	}

	text := bytes.TrimSpace(nativebytes.BeforeNUL(data))
	if bytes.HasPrefix(text, []byte("-----BEGIN ")) {
		der, err := parseCertificatePEM(text)
		if err != nil {
			return nil, err
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate PEM contains invalid DER: %w", ErrInvalidInput, err)
		}

		return cert, nil
	}

	if der, err := base64.StdEncoding.AppendDecode(nil, text); err == nil && len(der) != 0 {
		if cert, err := x509.ParseCertificate(der); err == nil {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("%w: certificate output is not DER, PEM, or base64 DER", ErrInvalidInput)
}

func isEmptyNativeCertificate(data []byte) bool {
	if len(bytes.Trim(data, "\x00 \t\r\n")) == 0 {
		return true
	}

	// DER certificates always start with an ASN.1 SEQUENCE. Other supported
	// representations are textual, so bytes beyond their first C terminator do
	// not make an otherwise empty native result non-empty.
	return data[0] != 0x30 && len(bytes.TrimSpace(nativebytes.BeforeNUL(data))) == 0
}

func (info *CertificateInfo) applyKazakhstanSubjectDetails() {
	info.IIN = prefixedNativeAttributeValue(info.SubjectSerialNumber, kzIINPrefix)
	info.BIN = prefixedNativeAttributeValue(info.SubjectOrganizationalUnit, kzBINPrefix)

	for _, policy := range info.Policies {
		info.applyKazakhstanPolicy(policy)
	}

	if info.SubjectType == CertificateSubjectUnknown {
		info.SubjectType = inferKazakhstanSubjectType(info)
	}
}

func (info *CertificateInfo) applyKazakhstanPolicy(policy string) {
	switch {
	case policy == kzPolicyPerson:
		info.SubjectType = CertificateSubjectPerson
	case policy == kzPolicyPersonSystem:
		info.SubjectType = CertificateSubjectPerson
		info.addCertificateRole(CertificateRolePersonSystem)
	case policy == kzPolicyLegalEntity:
		info.SubjectType = CertificateSubjectLegalEntity
	case policy == kzPolicyFirstHead:
		info.SubjectType = CertificateSubjectLegalEntity
		info.addCertificateRole(CertificateRoleFirstHead)
	case policy == kzPolicySigner:
		info.SubjectType = CertificateSubjectLegalEntity
		info.addCertificateRole(CertificateRoleSigner)
	case policy == kzPolicyFinancialSigner:
		info.SubjectType = CertificateSubjectLegalEntity
		info.addCertificateRole(CertificateRoleFinancialSigner)
	case policy == kzPolicyHR:
		info.SubjectType = CertificateSubjectLegalEntity
		info.addCertificateRole(CertificateRoleHR)
	case policy == kzPolicyEmployee:
		info.SubjectType = CertificateSubjectLegalEntity
		info.addCertificateRole(CertificateRoleEmployee)
	case policy == kzPolicyLegalEntitySystem || strings.HasPrefix(policy, kzPolicyLegalEntitySystemPfx):
		info.SubjectType = CertificateSubjectLegalEntity
		info.addCertificateRole(CertificateRoleLegalEntitySystem)
	}
}

func (info *CertificateInfo) addCertificateRole(role CertificateRole) {
	if slices.Contains(info.Roles, role) {
		return
	}

	info.Roles = append(info.Roles, role)
}

func inferKazakhstanSubjectType(info *CertificateInfo) CertificateSubjectType {
	switch {
	case info.BIN != "":
		return CertificateSubjectLegalEntity
	case info.IIN != "":
		return CertificateSubjectPerson
	default:
		return CertificateSubjectUnknown
	}
}

func prefixedNativeAttributeValue(value, prefix string) string {
	for _, attributeValue := range splitNativeAttributeValues(value) {
		if v, ok := strings.CutPrefix(attributeValue, prefix); ok {
			return strings.TrimSpace(v)
		}
	}

	return ""
}

func parseNativeCertificateTime(field, value string) (time.Time, error) {
	raw := nativePropertyValue(value)
	if raw == "" {
		return time.Time{}, nil
	}

	layouts := []string{
		"02.01.2006 15:04:05 MST",
		"02.01.2006 15:04:05 -0700",
		time.RFC3339,
	}

	for _, layout := range layouts {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed, nil
		}
	}

	return time.Time{}, fmt.Errorf("%w: certificate %s time %q is not supported", ErrInvalidInput, field, raw)
}

func splitNativePropertyValues(value string) []string {
	return splitNativeValues(value, strings.TrimSpace)
}

func splitNativeAttributeValues(value string) []string {
	return splitNativeValues(value, nativePropertyValue)
}

func splitNativeValues(value string, normalize func(string) string) []string {
	value = nativePropertyValue(value)
	if value == "" {
		return nil
	}

	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})

	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = normalize(part)
		if part != "" {
			values = append(values, part)
		}
	}

	return values
}

func nativePropertyValue(value string) string {
	value = strings.TrimSpace(value)

	if _, after, ok := strings.Cut(value, "="); ok {
		return strings.TrimSpace(after)
	}

	return value
}

func isKalkanErrorCode(err error, code ckalkan.ErrorCode) bool {
	got, ok := ckalkan.ErrorCodeOf(err)

	return ok && got == code
}
