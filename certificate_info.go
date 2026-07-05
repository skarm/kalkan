package kalkan

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
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
	// Policies contains parsed values from Policy.
	Policies []string
	// KeyUsages contains parsed values from KeyUsage.
	KeyUsages []string
	// ExtKeyUsages contains parsed values from ExtKeyUsage.
	ExtKeyUsages []string
}

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
	CertificateInfoDeltaCRLURL

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

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := validateBytesSize(certPEM, "certificate", c.configuredMaxInputSize()); err != nil {
		return nil, err
	}

	info := &CertificateInfo{}

	props := []struct {
		field    CertificateInfoField
		prop     ckalkan.CertProp
		optional bool
		apply    func(string) error
	}{
		{field: CertificateInfoSubject, prop: ckalkan.CertPropSubjectDN, apply: func(value string) error {
			info.Subject = value
			return nil
		}},
		{field: CertificateInfoSerialNumber, prop: ckalkan.CertPropCertSN, apply: func(value string) error {
			info.SerialNumber = value
			return nil
		}},
		{field: CertificateInfoValidFrom, prop: ckalkan.CertPropNotBefore, apply: func(value string) error {
			parsed, err := parseNativeCertificateTime("notBefore", value)
			if err != nil {
				return err
			}

			info.ValidFrom = parsed

			return nil
		}},
		{field: CertificateInfoValidUntil, prop: ckalkan.CertPropNotAfter, apply: func(value string) error {
			parsed, err := parseNativeCertificateTime("notAfter", value)
			if err != nil {
				return err
			}

			info.ValidUntil = parsed

			return nil
		}},
		{field: CertificateInfoIssuer, prop: ckalkan.CertPropIssuerDN, apply: func(value string) error {
			info.Issuer = value
			return nil
		}},
		{field: CertificateInfoPolicy, prop: ckalkan.CertPropPoliciesID, apply: func(value string) error {
			info.Policy = value
			info.Policies = splitNativePropertyValues(value)

			return nil
		}},
		{field: CertificateInfoKeyUsage, prop: ckalkan.CertPropKeyUsage, apply: func(value string) error {
			info.KeyUsage = value
			info.KeyUsages = splitNativePropertyValues(value)

			return nil
		}},
		{field: CertificateInfoExtKeyUsage, prop: ckalkan.CertPropExtKeyUsage, apply: func(value string) error {
			info.ExtKeyUsage = value
			info.ExtKeyUsages = splitNativePropertyValues(value)

			return nil
		}},
		{field: CertificateInfoAuthKeyID, prop: ckalkan.CertPropAuthKeyID, apply: func(value string) error {
			info.AuthKeyID = value
			return nil
		}},
		{field: CertificateInfoSubjKeyID, prop: ckalkan.CertPropSubjKeyID, apply: func(value string) error {
			info.SubjKeyID = value
			return nil
		}},
		{field: CertificateInfoAlgorithmSignCert, prop: ckalkan.CertPropSignatureAlg, apply: func(value string) error {
			info.AlgorithmSignCert = value
			return nil
		}},
		{field: CertificateInfoPublicKey, prop: ckalkan.CertPropPubKey, apply: func(value string) error {
			info.PublicKey = value
			return nil
		}},
		{field: CertificateInfoOCSPURL, prop: ckalkan.CertPropOCSP, optional: true, apply: func(value string) error {
			info.OCSPURL = value
			return nil
		}},
		{field: CertificateInfoCRLURL, prop: ckalkan.CertPropGetCRL, optional: true, apply: func(value string) error {
			info.CRLURL = value
			return nil
		}},
		{field: CertificateInfoDeltaCRLURL, prop: ckalkan.CertPropGetDeltaCRL, optional: true, apply: func(value string) error {
			info.DeltaCRLURL = value
			return nil
		}},
	}

	for _, item := range props {
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

		if err := item.apply(string(trimNativeCStringBytes(value))); err != nil {
			return nil, err
		}
	}

	return info, nil
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

	for signID := 0; signID < maxExtractedSignerCertificates; signID++ {
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
			return certs, nil
		}

		cert, err := parseNativeCertificate(out)
		if err != nil {
			return nil, fmt.Errorf("kalkan: parse signer certificate %d: %w", signID, err)
		}

		certs = append(certs, cert)
	}

	return nil, fmt.Errorf("%w: signer certificate count exceeds %d", ErrInvalidInput, maxExtractedSignerCertificates)
}

func parseNativeCertificate(data []byte) (*x509.Certificate, error) {
	if len(bytes.Trim(data, "\x00 \t\r\n")) == 0 {
		return nil, fmt.Errorf("%w: certificate output is empty", ErrInvalidInput)
	}

	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert, nil
	}

	text := bytes.TrimSpace(trimNativeCStringBytes(data))
	if block, _ := pem.Decode(text); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: certificate PEM block type must be CERTIFICATE, got %q", ErrInvalidInput, block.Type)
		}

		return x509.ParseCertificate(block.Bytes)
	}

	if der, err := base64.StdEncoding.AppendDecode(nil, text); err == nil && len(der) != 0 {
		if cert, err := x509.ParseCertificate(der); err == nil {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("%w: certificate output is not DER, PEM, or base64 DER", ErrInvalidInput)
}

func isEmptyNativeCertificate(data []byte) bool {
	return len(bytes.Trim(data, "\x00 \t\r\n")) == 0
}

func trimNativeCStringBytes(value []byte) []byte {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		return value[:index]
	}

	return value
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
