package isolated

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/skarm/kalkan"
)

var _ sdkClient = (*Client)(nil)

// Hash calculates a digest in the worker process.
func (c *Client) Hash(ctx context.Context, req kalkan.HashRequest) (*kalkan.Digest, error) {
	return callResult[*kalkan.Digest](c, ctx, opHash, req)
}

// SignHash signs an already calculated digest in the worker process.
func (c *Client) SignHash(ctx context.Context, req kalkan.SignHashRequest) (*kalkan.CMS, error) {
	return callResult[*kalkan.CMS](c, ctx, opSignHash, req)
}

// SignCMS signs data and returns a CMS container.
func (c *Client) SignCMS(ctx context.Context, req kalkan.SignCMSRequest) (*kalkan.CMS, error) {
	return callResult[*kalkan.CMS](c, ctx, opSignCMS, req)
}

// VerifyCMS verifies a CMS container in the worker process.
func (c *Client) VerifyCMS(ctx context.Context, req kalkan.VerifyCMSRequest) (*kalkan.Verification, error) {
	return callResult[*kalkan.Verification](c, ctx, opVerifyCMS, req)
}

// SignXML signs an XML document in the worker process.
func (c *Client) SignXML(ctx context.Context, req kalkan.SignXMLRequest) (*kalkan.SignedXML, error) {
	return callResult[*kalkan.SignedXML](c, ctx, opSignXML, req)
}

// VerifyXML verifies XML with the same SOAP binding checks as
// [kalkan.Client.VerifyXML].
func (c *Client) VerifyXML(ctx context.Context, req kalkan.VerifyXMLRequest) (*kalkan.Verification, error) {
	return callResult[*kalkan.Verification](c, ctx, opVerifyXML, req)
}

// SignWSSE creates a WS-Security XML signature in the worker process.
func (c *Client) SignWSSE(ctx context.Context, req kalkan.SignWSSERequest) (*kalkan.SignedXML, error) {
	return callResult[*kalkan.SignedXML](c, ctx, opSignWSSE, req)
}

// ValidateCertificate validates a certificate in the worker process.
func (c *Client) ValidateCertificate(ctx context.Context, req kalkan.ValidateCertificateRequest) (*kalkan.CertificateValidation, error) {
	return callResult[*kalkan.CertificateValidation](c, ctx, opValidateCertificate, req)
}

// LoadKeyStore selects a private-key container in this client's worker process.
func (c *Client) LoadKeyStore(ctx context.Context, store kalkan.KeyStore) error {
	return callVoid(c, ctx, opLoadKeyStore, store)
}

// LoadTrustedCertificate loads trust retained by the worker until it closes.
func (c *Client) LoadTrustedCertificate(ctx context.Context, certificate kalkan.TrustedCertificate) error {
	return callVoid(c, ctx, opLoadTrustedCertificate, certificate)
}

// SetProxy changes the worker's native HTTP proxy configuration.
func (c *Client) SetProxy(ctx context.Context, proxy kalkan.Proxy) error {
	return callVoid(c, ctx, opSetProxy, proxy)
}

// SignZIP signs a file into a ZIP container in the worker process.
func (c *Client) SignZIP(ctx context.Context, req kalkan.SignZIPRequest) (*kalkan.SignedZIP, error) {
	return callResult[*kalkan.SignedZIP](c, ctx, opSignZIP, req)
}

// VerifyZIP verifies a ZIP container in the worker process.
func (c *Client) VerifyZIP(ctx context.Context, req kalkan.VerifyZIPRequest) (*kalkan.Verification, error) {
	return callResult[*kalkan.Verification](c, ctx, opVerifyZIP, req)
}

// ExtractZIPSignerCertificate returns a ZIP signer's native certificate bytes.
func (c *Client) ExtractZIPSignerCertificate(ctx context.Context, req kalkan.ExtractZIPSignerCertificateRequest) ([]byte, error) {
	return callResult[[]byte](c, ctx, opExtractZIPSignerCertificate, req)
}

// X509ExportCertificateFromStore exports the worker's loaded signing certificate.
func (c *Client) X509ExportCertificateFromStore(ctx context.Context) (*x509.Certificate, error) {
	var certificate *x509.Certificate

	err := c.call(ctx, opX509ExportCertificateFromStore, nil, func(payload wirePayload) error {
		var der []byte
		if err := decodeResult(opX509ExportCertificateFromStore, payload, &der); err != nil {
			return err
		}

		if der == nil {
			return nil
		}

		var err error

		certificate, err = decodeCertificate(der)

		return err
	})
	if err != nil {
		return nil, err
	}

	return certificate, nil
}

// X509CertificateGetInfo retrieves the default native certificate properties.
func (c *Client) X509CertificateGetInfo(ctx context.Context, certificate *x509.Certificate) (*kalkan.CertificateInfo, error) {
	return callResult[*kalkan.CertificateInfo](c, ctx, opX509CertificateGetInfo, certificate)
}

// X509CertificateGetInfoFields retrieves the selected native certificate properties.
func (c *Client) X509CertificateGetInfoFields(ctx context.Context, certificate *x509.Certificate, fields kalkan.CertificateInfoField) (*kalkan.CertificateInfo, error) {
	return callResult[*kalkan.CertificateInfo](c, ctx, opX509CertificateGetInfoFields, certificateInfoFieldsRequest{
		Certificate: certificate, Fields: fields,
	})
}

// GetCertFromCMS extracts certificates embedded in a CMS container.
func (c *Client) GetCertFromCMS(ctx context.Context, source kalkan.Source) ([]*x509.Certificate, error) {
	return callCertificates(c, ctx, opGetCertFromCMS, source)
}

// GetCertFromXML extracts one certificate per XML signature in document order.
func (c *Client) GetCertFromXML(ctx context.Context, source kalkan.Source) ([]*x509.Certificate, error) {
	return callCertificates(c, ctx, opGetCertFromXML, source)
}

// GetTimeFromSig returns the timestamp embedded for the first CMS signer.
func (c *Client) GetTimeFromSig(ctx context.Context, source kalkan.Source) (time.Time, error) {
	return callResult[time.Time](c, ctx, opGetTimeFromSig, source)
}

// GetSigAlgFromXML returns the native XML signature algorithm identifier.
func (c *Client) GetSigAlgFromXML(ctx context.Context, source kalkan.Source) (string, error) {
	return callResult[string](c, ctx, opGetSigAlgFromXML, source)
}

func callResult[Result any](client *Client, ctx context.Context, operation string, request any) (Result, error) {
	var result Result

	err := client.call(ctx, operation, request, func(payload wirePayload) error {
		return decodeResult(operation, payload, &result)
	})
	if err != nil {
		var zero Result
		return zero, err
	}

	return result, nil
}

func callVoid(client *Client, ctx context.Context, operation string, request any) error {
	return client.call(ctx, operation, request, func(payload wirePayload) error {
		var result any
		return decodeResult(operation, payload, &result)
	})
}

func callCertificates(client *Client, ctx context.Context, operation string, source kalkan.Source) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	err := client.call(ctx, operation, source, func(payload wirePayload) error {
		var encoded [][]byte
		if err := decodeResult(operation, payload, &encoded); err != nil {
			return err
		}

		if encoded == nil {
			return nil
		}

		certificates = make([]*x509.Certificate, len(encoded))
		for i, der := range encoded {
			if der == nil {
				continue
			}

			var err error

			certificates[i], err = decodeCertificate(der)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return certificates, nil
}

func decodeCertificate(der []byte) (*x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed certificate in worker response", ErrProtocol)
	}

	return certificate, nil
}
