package kalkan

import (
	"context"
	"fmt"

	"github.com/skarm/kalkan/ckalkan"
)

// CertificateTimeCheck controls certificate-time validation during
// signing, signature verification, and certificate validation. Its zero value
// uses KalkanCrypt's default checks.
type CertificateTimeCheck int

const (
	// DefaultCertificateTimeCheck keeps KalkanCrypt's default certificate-time
	// validation behavior.
	DefaultCertificateTimeCheck CertificateTimeCheck = iota
	// SkipCertificateTimeCheck sets KC_NOCHECKCERTTIME and weakens certificate validation.
	// Enable it only when an external archival policy permits verification
	// without certificate-time checks.
	SkipCertificateTimeCheck
)

// CMSOutputFormat selects the representation returned by CMS signing operations.
type CMSOutputFormat int

const (
	// CMSOutputDER selects CMS bytes in ASN.1 DER format.
	// This is the default output format.
	// [Client.VerifyCMS] accepts this output through [Bytes] or [DER] sources.
	CMSOutputDER CMSOutputFormat = iota
	// CMSOutputBase64 selects base64 text for DER CMS bytes without PEM
	// delimiters.
	// Use it for text transports or JSON fields.
	CMSOutputBase64
	// CMSOutputPEM selects PEM text with base64 DER, delimiters, and line
	// breaks.
	// Use it for PEM tools and text transfers.
	CMSOutputPEM
)

// SignCMSRequest describes CMS signing input.
type SignCMSRequest struct {
	// Alias selects a loaded key alias. Empty alias lets KalkanCrypt use its
	// default loaded key when the native library supports that behavior.
	Alias string
	// Data is the payload to sign. The zero-value Source is rejected; use
	// Bytes(nil) or Bytes([]byte{}) only when an explicit empty payload is
	// intended. With ExistingSignature, Base64 and PEM payload files are decoded in
	// memory before signing; raw and DER files are passed directly to the backend.
	// PEM append payloads must contain exactly one block.
	// Without ExistingSignature, an attached CMS supplied as DER, PEM or base64
	// receives an additional signer. Other PEM payloads are signed as literal text.
	Data Source
	// ExistingSignature optionally supplies an in-memory CMS to which a signer
	// is added. DER, base64 and a single PEM block are accepted. Data must be the
	// same payload and Detached must match the existing container. The Java backend
	// verifies existing signatures, trust and revocation before adding the signer.
	ExistingSignature Source
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
	// CertificateTimeCheck controls native certificate-time validation for the
	// new signature.
	CertificateTimeCheck CertificateTimeCheck
}

// VerifyCMSRequest describes CMS verification input.
type VerifyCMSRequest struct {
	// Alias is forwarded to KalkanCrypt's VerifyData alias parameter.
	Alias string
	// Signature is the CMS/signature input. Use File for large signatures or
	// Bytes for in-memory raw CMS bytes.
	Signature Source
	// Data is the detached payload.
	// It is valid only when Detached is true and must use an in-memory source.
	// KalkanCrypt applies KC_IN_FILE to the CMS signature input during
	// verification.
	//
	// Detached verification rejects the zero-value Source.
	// Bytes(nil) or Bytes([]byte{}) supplies an explicit empty detached payload.
	Data Source
	// Detached verifies a detached CMS signature.
	Detached bool
	// Encoding supplies the default when Signature uses EncodingAuto.
	// [File] uses EncodingAuto.
	// [Bytes], [Base64], [PEM], and [DER] set an explicit encoding that
	// overrides this field.
	// Go does not inspect file contents to infer their encoding.
	Encoding Encoding
	// SignerID selects a signer certificate from multi-signer data.
	SignerID int
	// CertificateTimeCheck controls KalkanCrypt certificate-time validation.
	CertificateTimeCheck CertificateTimeCheck
}

// CMS contains a signature from [Client.SignCMS] or [Client.SignHash].
// The request's OutputFormat selects its representation.
type CMS struct {
	// Data contains CMS output bytes. By default this is raw DER CMS; when a
	// signing request sets OutputFormat, Data contains base64 or PEM
	// text bytes instead.
	Data []byte
}

// Verification contains diagnostics and optional extracted data from
// [Client.VerifyCMS], [Client.VerifyXML], or [Client.VerifyZIP].
// These methods return Verification after successful verification and errors on failure.
type Verification struct {
	// Info contains verification diagnostics from KalkanCrypt.
	Info string
	// Data contains attached CMS payload data when KalkanCrypt returns it. XML
	// and ZIP verification leave it empty.
	Data []byte
	// SignerCert contains the selected signer certificate when KalkanCrypt
	// returns it. XML and ZIP verification leave it empty.
	SignerCert []byte
}

// SignCMS signs req.Data and returns a [CMS] container.
// The default output format is raw DER CMS.
// For attached signatures, existing CMS input in DER, PEM, or base64 format
// receives an additional signer.
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

	existing, err := existingCMSInput(req.ExistingSignature, c.configuredMaxInputSize())
	if err != nil {
		return nil, err
	}

	if len(existing) != 0 {
		data, flags, err = cmsAppendData(ctx, data, flags, c.configuredMaxInputSize())
		if err != nil {
			return nil, err
		}
	}

	out, err := withOperationsResult(c, ctx, "SignCMS", func(operations cmsOperations) ([]byte, error) {
		return operations.SignData(ckalkan.SignDataRequest{
			Alias:     req.Alias,
			Flags:     flags,
			Data:      data,
			Signature: existing,
		})
	})
	if err != nil {
		return nil, err
	}

	return &CMS{Data: out}, nil
}

// VerifyCMS verifies req.Signature and returns native diagnostics.
// The result can also contain decoded data and a signer certificate.
//
// The Linux SDK cannot reliably verify empty CMS payloads.
// For attached empty CMS, this binding rejects the SDK's negative output
// length.
// Detached empty verification returns [ckalkan.ErrorVerifyNoData], even for a
// valid signature.
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

	maxInputSize := c.configuredMaxInputSize()

	signature, flags, err := cmsSignatureInput(req.Signature, req.Encoding, maxInputSize)
	if err != nil {
		return nil, err
	}

	data, dataFlags, err := cmsDataInput(req.Data, maxInputSize)
	if err != nil {
		return nil, err
	}

	if req.Detached && req.Data.file {
		return nil, fmt.Errorf("%w: detached CMS data must be an in-memory source; KalkanCrypt accepts a file source only for the CMS signature during verification", ErrInvalidInput)
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

	// Validation already rejected detached data file sources.
	if req.Signature.file {
		flags |= ckalkan.InFile
	}

	result, err := withOperationsResult(c, ctx, "VerifyCMS", func(operations cmsOperations) (ckalkan.VerifyDataResult, error) {
		return operations.VerifyData(ckalkan.VerifyDataRequest{
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
