package kalkan

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

const maxExtractedSignerCertificates = 64

// CertificateInfo contains selected KalkanCrypt certificate properties.
type CertificateInfo struct {
	// Subject is the native subject distinguished name string.
	Subject string
	// SerialNumber is the native certificate serial number string.
	SerialNumber string
	// ValidFrom is the parsed native notBefore value.
	ValidFrom time.Time
	// ValidUntil is the parsed native notAfter value.
	ValidUntil time.Time
	// Issuer is the native issuer distinguished name string.
	Issuer string
	// Policy is the native certificate policies string.
	Policy string
	// KeyUsage is the native key usage string.
	KeyUsage string
	// ExtKeyUsage is the native extended key usage string.
	ExtKeyUsage string
	// AuthKeyID is the native authority key identifier string.
	AuthKeyID string
	// SubjKeyID is the native subject key identifier string.
	SubjKeyID string
	// AlgorithmSignCert is the native certificate signature algorithm string.
	AlgorithmSignCert string
	// PublicKey is the native public key string.
	PublicKey string
	// OCSPURL is the native OCSP responder string.
	OCSPURL string
	// CRLURL is the native CRL distribution point string.
	CRLURL string
	// DeltaCRLURL is the native delta CRL distribution point string.
	DeltaCRLURL string
	// SubjectCountry is the native subject country value.
	SubjectCountry string
	// SubjectSerialNumber is the native subject serialNumber value.
	SubjectSerialNumber string
	// SubjectOrganization is the native subject organization value.
	SubjectOrganization string
	// SubjectOrganizationalUnit is the native subject organizational unit value.
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
// KalkanCrypt. Use X509CertificateGetInfo for the full legacy set.
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
	// CertificateInfoAlgorithmSignCert requests the signature algorithm.
	CertificateInfoAlgorithmSignCert
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
	CertificateInfoAlgorithmSignCert |
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
	{field: CertificateInfoAlgorithmSignCert, prop: ckalkan.CertPropSignatureAlg},
	{field: CertificateInfoPublicKey, prop: ckalkan.CertPropPubKey},
	{field: CertificateInfoOCSPURL, prop: ckalkan.CertPropOCSP, optional: true},
	{field: CertificateInfoCRLURL, prop: ckalkan.CertPropGetCRL, optional: true},
	{field: CertificateInfoDeltaCRLURL, prop: ckalkan.CertPropGetDeltaCRL, optional: true},
}

// X509ExportCertificateFromStore exports the default certificate from
// KalkanCrypt's native store and parses it as an x509 certificate.
func (c *Client) X509ExportCertificateFromStore(ctx context.Context) (*x509.Certificate, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	out, err := withLockedLibraryResult(c, ctx, "X509ExportCertificateFromStore", func(native certificates) ([]byte, error) {
		return native.X509ExportCertificateFromStore("", ckalkan.CertDER)
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

// X509CertificateGetInfo collects commonly used certificate properties through
// KalkanCrypt's native X509CertificateGetInfo calls.
func (c *Client) X509CertificateGetInfo(ctx context.Context, cert *x509.Certificate) (*CertificateInfo, error) {
	return c.X509CertificateGetInfoFields(ctx, cert, CertificateInfoAllFields)
}

// X509CertificateGetInfoFields collects selected certificate properties through
// KalkanCrypt's native X509CertificateGetInfo calls.
func (c *Client) X509CertificateGetInfoFields(ctx context.Context, cert *x509.Certificate, fields CertificateInfoField) (*CertificateInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
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

	certPEM := c.cachedPEMForCertificate(cert.Raw)
	if certPEM == nil {
		certPEM = c.encodeAndCacheCertificatePEM(cert.Raw)
	}

	if err := validateBytesSize(certPEM, "certificate", c.configuredMaxInputSize()); err != nil {
		return nil, err
	}

	info := &CertificateInfo{}

	for _, item := range certificateInfoProperties {
		if fields&item.field == 0 {
			continue
		}

		value, err := withLockedLibraryResult(c, ctx, "X509CertificateGetInfo", func(native certificates) ([]byte, error) {
			return native.X509CertificateGetInfo(certPEM, item.prop)
		})
		if err != nil {
			if item.optional && isKalkanErrorCode(err, ckalkan.ErrorGetCertProp) {
				continue
			}

			return nil, fmt.Errorf("kalkan: get certificate property %v: %w", item.prop, err)
		}

		if err := applyCertificateInfoProperty(info, item.field, string(bytesBeforeNULTerminator(value))); err != nil {
			return nil, err
		}
	}

	info.applyKazakhstanSubjectDetails()

	return info, nil
}

type entry struct {
	der []byte
	pem []byte
}

func (c *Client) cachedPEMForCertificate(der []byte) []byte {
	if cached := c.pemCache.Load(); cached != nil && bytes.Equal(cached.der, der) {
		return cached.pem
	}

	return nil
}

func (c *Client) encodeAndCacheCertificatePEM(der []byte) []byte {
	encoded := encodeCertificatePEM(der)
	c.pemCache.Store(&entry{
		der: slices.Clone(der),
		pem: encoded,
	})

	return encoded
}

func encodeCertificatePEM(der []byte) []byte {
	const (
		header       = "-----BEGIN CERTIFICATE-----\n"
		footer       = "-----END CERTIFICATE-----\n"
		pemLineWidth = 64
		rawChunkSize = pemLineWidth / 4 * 3
	)

	encodedLen := base64.StdEncoding.EncodedLen(len(der))
	lineCount := (encodedLen + pemLineWidth - 1) / pemLineWidth
	logicalLen := len(header) + encodedLen + lineCount + len(footer)
	out := make([]byte, logicalLen+1)
	offset := copy(out, header)

	for len(der) > 0 {
		chunkLen := min(len(der), rawChunkSize)
		chunkEncodedLen := base64.StdEncoding.EncodedLen(chunkLen)
		base64.StdEncoding.Encode(out[offset:offset+chunkEncodedLen], der[:chunkLen])
		offset += chunkEncodedLen
		out[offset] = '\n'
		offset++
		der = der[chunkLen:]
	}

	copy(out[offset:], footer)

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
	case CertificateInfoAlgorithmSignCert:
		info.AlgorithmSignCert = value
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
		flags |= ckalkan.InFile
	}

	return collectSignerCertificates(ctx, func(signID int) ([]byte, error) {
		return withLockedLibraryResult(c, ctx, "GetCertFromCMS", func(native cmsSignatures) ([]byte, error) {
			return native.GetCertFromCMS(value, signID, flags)
		})
	})
}

// GetTimeFromSig returns the timestamp embedded in a CMS signature.
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

	return withLockedLibraryResult(c, ctx, "GetTimeFromSig", func(native cmsSignatures) (time.Time, error) {
		return native.GetTimeFromSig(value, flags, 0)
	})
}

// GetCertFromXML extracts signer certificates embedded in signed XML.
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

	return collectSignerCertificates(ctx, func(signID int) ([]byte, error) {
		return withLockedLibraryResult(c, ctx, "GetCertFromXML", func(native xmlSignatures) ([]byte, error) {
			return native.GetCertFromXML(value, signID)
		})
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

	return withLockedLibraryResult(c, ctx, "GetSigAlgFromXML", func(native xmlSignatures) (string, error) {
		return native.GetSigAlgFromXML(value)
	})
}

func collectSignerCertificates(ctx context.Context, fetch func(signID int) ([]byte, error)) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for signID := 0; ; signID++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		out, err := fetch(signID)
		if err != nil {
			if isKalkanErrorCode(err, ckalkan.ErrorCertNotFound) {
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

	text := bytes.TrimSpace(bytesBeforeNULTerminator(data))
	if bytes.HasPrefix(text, []byte("-----BEGIN ")) {
		block, rest := pem.Decode(text)
		if block == nil {
			return nil, fmt.Errorf("%w: certificate output contains invalid PEM", ErrInvalidInput)
		}

		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%w: certificate PEM contains trailing data", ErrInvalidInput)
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: certificate PEM block type must be CERTIFICATE, got %q", ErrInvalidInput, block.Type)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
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
	return data[0] != 0x30 && len(bytes.TrimSpace(bytesBeforeNULTerminator(data))) == 0
}

// bytesBeforeNULTerminator returns the meaningful prefix of a native textual
// result. Bytes after a C-string terminator are unspecified by that contract.
func bytesBeforeNULTerminator(value []byte) []byte {
	index := bytes.IndexByte(value, 0)
	if index >= 0 {
		return value[:index:index]
	}

	return value[:len(value):len(value)]
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
	value = nativePropertyValue(value)
	if value == "" {
		return nil
	}

	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})

	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}

	return values
}

func splitNativeAttributeValues(value string) []string {
	value = nativePropertyValue(value)
	if value == "" {
		return nil
	}

	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})

	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = nativePropertyValue(part)
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
