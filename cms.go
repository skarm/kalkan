package kalkan

import (
	"context"
	"fmt"
	"strconv"

	"github.com/skarm/kalkan/ckalkan"
)

// CertificateTimeCheck controls certificate-time checks performed by KalkanCrypt
// while verifying signatures or certificate chains.
type CertificateTimeCheck int

const (
	// DefaultCertificateTimeCheck keeps KalkanCrypt's default certificate-time
	// validation behavior.
	DefaultCertificateTimeCheck CertificateTimeCheck = iota
	// SkipCertificateTimeCheck sets KC_NOCHECKCERTTIME. It can be useful when
	// verifying signatures according to an external archival policy, but it
	// weakens validation and should be enabled only when that policy explicitly
	// allows it.
	SkipCertificateTimeCheck
)

// CMSOutputFormat selects the representation returned by CMS signing operations.
type CMSOutputFormat int

const (
	// CMSOutputDER returns raw binary ASN.1 DER CMS bytes. This is the default
	// output format and can be passed back to VerifyCMS using Bytes or DER
	// sources.
	CMSOutputDER CMSOutputFormat = iota
	// CMSOutputBase64 returns base64 text for the DER CMS bytes, without PEM
	// header/footer armor. Use it for text-only transports or JSON fields.
	CMSOutputBase64
	// CMSOutputPEM returns PEM-armored text: base64 DER plus header/footer and
	// line wrapping. Use it for copy/paste workflows and PEM-oriented tools.
	CMSOutputPEM
)

// SignCMSRequest describes CMS signing input.
type SignCMSRequest struct {
	// Alias selects a loaded key alias. Empty alias lets KalkanCrypt use its
	// default loaded key when the native library supports that behavior.
	Alias string
	// Data is the payload to sign. The zero-value Source is rejected; use
	// Bytes(nil) or Bytes([]byte{}) only when an explicit empty payload is
	// intended.
	Data Source
	// Detached requests a detached CMS signature.
	Detached bool
	// Timestamp requests a TSA timestamp token.
	Timestamp bool
	// IncludeCertificate asks KalkanCrypt to embed the signing certificate in
	// the CMS container.
	IncludeCertificate bool
	// OutputFormat selects the CMS output representation. The zero value
	// returns raw DER CMS bytes.
	OutputFormat CMSOutputFormat
	// CertificateTimeCheck controls KalkanCrypt certificate-time validation while
	// building the signature.
	CertificateTimeCheck CertificateTimeCheck
}

// VerifyCMSRequest describes CMS verification input.
type VerifyCMSRequest struct {
	// Alias is forwarded to KalkanCrypt's VerifyData alias parameter.
	Alias string
	// Signature is the CMS/signature input. Use File for large signatures or
	// Bytes for in-memory raw CMS bytes.
	Signature Source
	// Data is the detached payload. It is valid only when Detached is true. For
	// detached verification the zero-value Source is rejected; Bytes(nil) or
	// Bytes([]byte{}) means an explicit empty detached payload.
	Data Source
	// Detached verifies a detached CMS signature.
	Detached bool
	// Encoding describes the signature encoding when Signature does not specify
	// one explicitly. It is most important for File sources because Go does not
	// inspect file contents.
	Encoding Encoding
	// SignerID selects a signer certificate from multi-signer data.
	SignerID int
	// CertificateTimeCheck controls KalkanCrypt certificate-time validation.
	CertificateTimeCheck CertificateTimeCheck
}

// CMS is a CMS signature returned by SignCMS.
type CMS struct {
	// Data contains CMS output bytes. By default this is raw DER CMS; when a
	// signing request sets OutputFormat, Data contains native base64 or PEM
	// text bytes instead.
	Data []byte
}

// Verification is returned by CMS, XML, and ZIP verification operations.
type Verification struct {
	// Info is KalkanCrypt's native verification information string.
	Info string
	// Data contains attached CMS payload data when KalkanCrypt returns it. XML
	// and ZIP verification leave it empty.
	Data []byte
	// SignerCert contains the selected signer certificate when KalkanCrypt
	// returns it. XML and ZIP verification leave it empty.
	SignerCert []byte
}

// SignCMS signs data and returns CMS output bytes. The default output format is
// raw DER CMS.
func (c *Client) SignCMS(ctx context.Context, req SignCMSRequest) (*CMS, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := rejectEmbeddedNUL("alias", req.Alias); err != nil {
		return nil, err
	}

	if !req.Data.isSet() {
		return nil, fmt.Errorf("%w: CMS data is required", ErrInvalidInput)
	}

	if err := validateEncoding(req.Data.encoding); err != nil {
		return nil, err
	}

	if err := validateMemorySourceSize(req.Data, "CMS data", c.configuredMaxInputSize()); err != nil {
		return nil, err
	}

	data, err := req.Data.bytesOrPath()
	if err != nil {
		return nil, err
	}

	outputFlags, err := cmsOutputFlag(req.OutputFormat)
	if err != nil {
		return nil, err
	}

	flags := ckalkan.SignCMS | outputFlags
	if req.Detached {
		flags |= ckalkan.DetachedData
	}

	if req.Timestamp {
		flags |= ckalkan.WithTimestamp
	}

	if req.IncludeCertificate {
		flags |= ckalkan.WithCert
	}

	checkFlags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	flags |= checkFlags

	if req.Data.file {
		flags |= ckalkan.InFile
	}

	flags |= inputFlag(effectiveEncoding(req.Data, EncodingRaw))

	out, err := withLockedLibraryResult(c, ctx, "SignCMS", func(native cmsSignatures) ([]byte, error) {
		return native.SignData(ckalkan.SignDataRequest{
			Alias: req.Alias,
			Flags: flags,
			Data:  data,
		})
	})
	if err != nil {
		return nil, err
	}

	return &CMS{Data: out}, nil
}

// VerifyCMS verifies an attached or detached CMS signature.
func (c *Client) VerifyCMS(ctx context.Context, req VerifyCMSRequest) (*Verification, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := rejectEmbeddedNUL("alias", req.Alias); err != nil {
		return nil, err
	}

	if err := validateEncoding(req.Encoding); err != nil {
		return nil, err
	}

	if err := validateSignerID("SignerID", req.SignerID); err != nil {
		return nil, err
	}

	if !req.Detached && !req.Data.isZero() {
		return nil, fmt.Errorf("%w: detached CMS data requires detached verification", ErrInvalidInput)
	}

	if req.Detached && req.Data.isZero() {
		return nil, fmt.Errorf("%w: detached CMS data is required for detached verification", ErrInvalidInput)
	}

	if req.Detached && (req.Signature.file != req.Data.file) {
		return nil, fmt.Errorf("%w: detached CMS file verification requires both signature and data as file sources", ErrInvalidInput)
	}

	maxInputSize := c.configuredMaxInputSize()

	signature, flags, err := cmsSignatureInput(req.Signature, req.Encoding, maxInputSize)
	if err != nil {
		return nil, err
	}

	data, dataFlags, err := cmsDataInput(req.Data, maxInputSize)
	if err != nil {
		return nil, err
	}

	flags |= ckalkan.SignCMS | dataFlags

	if req.Detached {
		flags |= ckalkan.DetachedData
	}

	checkFlags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	flags |= checkFlags

	if req.Signature.file || req.Data.file {
		flags |= ckalkan.InFile
	}

	result, err := withLockedLibraryResult(c, ctx, "VerifyCMS", func(native cmsSignatures) (ckalkan.VerifyDataResult, error) {
		return native.VerifyData(ckalkan.VerifyDataRequest{
			Alias:     req.Alias,
			Flags:     flags,
			Data:      data,
			Signature: signature,
			CertID:    req.SignerID,
		})
	})
	if err != nil {
		return nil, err
	}

	return &Verification{
		Info:       result.VerifyInfo,
		Data:       result.Data,
		SignerCert: result.Cert,
	}, nil
}

func cmsSignatureInput(source Source, fallback Encoding, maxInputSize int64) ([]byte, ckalkan.Flag, error) {
	if source.isZero() {
		return nil, 0, fmt.Errorf("%w: CMS signature is required", ErrInvalidInput)
	}

	if err := validateMemorySourceSize(source, "CMS signature", maxInputSize); err != nil {
		return nil, 0, err
	}

	value, err := source.bytesOrPath()
	if err != nil {
		return nil, 0, err
	}

	if !source.file && len(value) == 0 {
		return nil, 0, fmt.Errorf("%w: CMS signature is empty", ErrInvalidInput)
	}

	encoding := effectiveEncoding(source, fallback)
	switch encoding {
	case EncodingAuto, EncodingRaw, EncodingDER:
		return value, ckalkan.InDER, nil
	case EncodingBase64:
		return value, ckalkan.InBase64, nil
	case EncodingPEM:
		return value, ckalkan.InPEM, nil
	default:
		return nil, 0, fmt.Errorf("%w: unknown CMS signature encoding %d", ErrInvalidInput, encoding)
	}
}

func cmsDataInput(source Source, maxInputSize int64) ([]byte, ckalkan.Flag, error) {
	if source.isZero() {
		return nil, 0, nil
	}

	if err := validateMemorySourceSize(source, "detached CMS data", maxInputSize); err != nil {
		return nil, 0, err
	}

	value, err := source.bytesOrPath()
	if err != nil {
		return nil, 0, err
	}

	encoding := effectiveEncoding(source, EncodingRaw)
	switch encoding {
	case EncodingPEM, EncodingDER:
		return nil, 0, fmt.Errorf("%w: detached CMS data encoding %s is not supported by KalkanCrypt; use raw or base64 data", ErrInvalidInput, encodingName(encoding))
	}

	if source.file {
		if encoding == EncodingBase64 {
			return value, ckalkan.In2Base64, nil
		}

		return value, 0, nil
	}

	switch encoding {
	case EncodingAuto, EncodingRaw:
		return value, 0, nil
	case EncodingBase64:
		return value, ckalkan.In2Base64, nil
	default:
		return nil, 0, fmt.Errorf("%w: unknown CMS data encoding %d", ErrInvalidInput, encoding)
	}
}

func encodingName(encoding Encoding) string {
	switch encoding {
	case EncodingAuto:
		return "auto"
	case EncodingRaw:
		return "raw"
	case EncodingBase64:
		return "base64"
	case EncodingPEM:
		return "PEM"
	case EncodingDER:
		return "DER"
	default:
		return strconv.Itoa(int(encoding))
	}
}

func inputFlag(encoding Encoding) ckalkan.Flag {
	switch encoding {
	case EncodingBase64:
		return ckalkan.InBase64
	case EncodingPEM:
		return ckalkan.InPEM
	case EncodingDER:
		return ckalkan.InDER
	default:
		return 0
	}
}

func cmsOutputFlag(format CMSOutputFormat) (ckalkan.Flag, error) {
	switch format {
	case CMSOutputDER:
		return ckalkan.OutDER, nil
	case CMSOutputBase64:
		return ckalkan.OutBase64, nil
	case CMSOutputPEM:
		return ckalkan.OutPEM, nil
	default:
		return 0, fmt.Errorf("%w: unknown CMS output format %d", ErrInvalidInput, format)
	}
}

func certificateTimeCheckFlag(check CertificateTimeCheck) (ckalkan.Flag, error) {
	switch check {
	case DefaultCertificateTimeCheck:
		return 0, nil
	case SkipCertificateTimeCheck:
		return ckalkan.NoCheckCertTime, nil
	default:
		return 0, fmt.Errorf("%w: unknown certificate time check %d", ErrInvalidInput, check)
	}
}
