package kalkan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

// CertificateValidationMode selects how KalkanCrypt checks certificate
// revocation while validating a certificate.
type CertificateValidationMode int

const (
	// CertificateValidationUnspecified is rejected by ValidateCertificate.
	CertificateValidationUnspecified CertificateValidationMode = iota
	// CertificateValidationNone disables external CRL/OCSP validation.
	CertificateValidationNone
	// CertificateValidationCRL validates against a CRL file or directory path.
	CertificateValidationCRL
	// CertificateValidationOCSP validates through an OCSP responder.
	CertificateValidationOCSP
)

func (m CertificateValidationMode) native() (ckalkan.ValidationType, error) {
	switch m {
	case CertificateValidationUnspecified:
		return 0, fmt.Errorf("%w: certificate validation mode is required", ErrInvalidInput)
	case CertificateValidationNone:
		return ckalkan.UseNothing, nil
	case CertificateValidationCRL:
		return ckalkan.UseCRL, nil
	case CertificateValidationOCSP:
		return ckalkan.UseOCSP, nil
	default:
		return 0, fmt.Errorf("%w: unknown certificate validation mode %d", ErrInvalidInput, m)
	}
}

// ValidateCertificateRequest describes certificate validation input.
type ValidateCertificateRequest struct {
	// Certificate is the certificate to validate. File sources are unsupported;
	// PEM and base64 are decoded to DER, while raw, auto, and DER are passed
	// unchanged.
	Certificate Source
	// Mode selects the revocation check. The zero value is invalid.
	Mode CertificateValidationMode
	// RevocationSource is a CRL path or OCSP URL. An empty OCSP source uses the
	// configured OCSP URL.
	RevocationSource string
	// CheckTime is the validation time. Zero lets KalkanCrypt use its own
	// default behavior.
	CheckTime time.Time
	// ReturnOCSPResponse requests the raw OCSP response from KalkanCrypt.
	ReturnOCSPResponse bool
	// CertificateTimeCheck controls KalkanCrypt certificate-time validation.
	CertificateTimeCheck CertificateTimeCheck
}

// CertificateValidation is returned by ValidateCertificate.
type CertificateValidation struct {
	// Info is KalkanCrypt's native validation information string.
	Info string
	// OCSPResponse contains the optional raw OCSP response returned by
	// KalkanCrypt when ReturnOCSPResponse is set.
	OCSPResponse []byte
}

// ValidateCertificate validates a certificate through KalkanCrypt.
func (c *Client) ValidateCertificate(ctx context.Context, req ValidateCertificateRequest) (*CertificateValidation, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cert, err := certificateValidationInput(req.Certificate, c.configuredMaxInputSize())
	if err != nil {
		return nil, err
	}

	validationType, err := req.Mode.native()
	if err != nil {
		return nil, err
	}

	if req.ReturnOCSPResponse && req.Mode != CertificateValidationOCSP {
		return nil, fmt.Errorf("%w: ReturnOCSPResponse requires OCSP certificate validation mode", ErrInvalidInput)
	}

	revocationSource, err := c.revocationSource(req)
	if err != nil {
		return nil, err
	}

	checkFlags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	flags := checkFlags

	if req.ReturnOCSPResponse {
		flags |= ckalkan.GetOCSPResponse
	}

	var checkTimeUnix int64
	if !req.CheckTime.IsZero() {
		checkTimeUnix = req.CheckTime.Unix()
	}

	result, err := withLockedLibraryResult(c, ctx, "ValidateCertificate", func(native certificates) (ckalkan.ValidateCertificateResult, error) {
		return native.X509ValidateCertificate(ckalkan.ValidateCertificateRequest{
			Certificate:    cert,
			ValidationType: validationType,
			ValidationPath: revocationSource,
			CheckTimeUnix:  checkTimeUnix,
			Flags:          flags,
		})
	})
	if err != nil {
		return nil, err
	}

	return &CertificateValidation{
		Info:         result.Info,
		OCSPResponse: result.OCSPResponse,
	}, nil
}

func (c *Client) revocationSource(req ValidateCertificateRequest) (string, error) {
	path := req.RevocationSource
	if path != "" {
		if req.Mode == CertificateValidationNone {
			return "", fmt.Errorf("%w: RevocationSource cannot be set when certificate validation mode is none", ErrInvalidInput)
		}

		if req.Mode == CertificateValidationOCSP {
			return normalizeNativeHTTPURL("certificate revocation OCSP URL", path)
		}

		return validateNativePathString("certificate revocation source", path)
	}

	switch req.Mode {
	case CertificateValidationUnspecified:
		return "", fmt.Errorf("%w: certificate validation mode is required", ErrInvalidInput)
	case CertificateValidationNone:
		return "", nil
	case CertificateValidationCRL:
		return "", fmt.Errorf("%w: CRL revocation source is empty", ErrInvalidInput)
	case CertificateValidationOCSP:
		if c == nil {
			return "", ErrClosed
		}

		return c.config.ocspURL, nil
	default:
		return "", fmt.Errorf("%w: unknown certificate validation mode %d", ErrInvalidInput, req.Mode)
	}
}

func certificateValidationInput(source Source, maxInputSize int64) ([]byte, error) {
	if source.isZero() {
		return nil, fmt.Errorf("%w: certificate is required", ErrInvalidInput)
	}

	if source.file {
		return nil, fmt.Errorf("%w: certificate file sources are not supported", ErrInvalidInput)
	}

	if err := validateEncoding(source.encoding); err != nil {
		return nil, err
	}

	if err := validateMemorySourceSize(source, "certificate", maxInputSize); err != nil {
		return nil, err
	}

	cert, err := source.bytesOrPath()
	if err != nil {
		return nil, err
	}

	if len(cert) == 0 {
		return nil, fmt.Errorf("%w: certificate is empty", ErrInvalidInput)
	}

	switch source.encoding {
	case EncodingPEM:
		cert = bytes.TrimSpace(cert)
		if !bytes.HasPrefix(cert, []byte("-----BEGIN ")) {
			if block, _ := pem.Decode(cert); block != nil {
				return nil, fmt.Errorf("%w: certificate PEM input contains leading data", ErrInvalidInput)
			}

			return nil, fmt.Errorf("%w: certificate PEM input is invalid", ErrInvalidInput)
		}

		block, rest := pem.Decode(cert)
		if block == nil {
			return nil, fmt.Errorf("%w: certificate PEM input is invalid", ErrInvalidInput)
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: certificate PEM block type must be CERTIFICATE, got %q", ErrInvalidInput, block.Type)
		}

		rest = bytes.TrimSpace(rest)
		if len(rest) != 0 {
			if next, _ := pem.Decode(rest); next != nil {
				return nil, fmt.Errorf("%w: certificate PEM input contains multiple PEM blocks", ErrInvalidInput)
			}

			return nil, fmt.Errorf("%w: certificate PEM input contains trailing data", ErrInvalidInput)
		}

		if len(block.Bytes) == 0 {
			return nil, fmt.Errorf("%w: certificate PEM input decodes to empty DER", ErrInvalidInput)
		}

		return block.Bytes, nil
	case EncodingBase64:
		der, err := base64.StdEncoding.AppendDecode(nil, bytes.TrimSpace(cert))
		if err != nil {
			return nil, fmt.Errorf("%w: certificate base64 input is invalid: %w", ErrInvalidInput, err)
		}

		if len(der) == 0 {
			return nil, fmt.Errorf("%w: certificate base64 input decodes to empty DER", ErrInvalidInput)
		}

		return der, nil
	case EncodingAuto, EncodingRaw, EncodingDER:
		return cert, nil
	default:
		return nil, fmt.Errorf("%w: unknown certificate encoding %d", ErrInvalidInput, source.encoding)
	}
}
