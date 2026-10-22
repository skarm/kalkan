package kalkan

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/internal/certsig"
)

// OCSPRevokedError reports an authenticated revoked status.
type OCSPRevokedError struct {
	// Endpoint is the OCSP responder URL that returned the verified status.
	Endpoint string
	// RevokedAt is the revocation time from the signed OCSP response.
	RevokedAt time.Time
}

// Error returns the revocation message with the revocation time.
func (e *OCSPRevokedError) Error() string {
	return "kalkan: OCSP certificate revoked at " + e.RevokedAt.Format(time.RFC3339)
}

// Unwrap returns a [ckalkan.KalkanError] with code
// [ckalkan.ErrorCertStatusRevoked].
func (e *OCSPRevokedError) Unwrap() error {
	return &ckalkan.KalkanError{Code: ckalkan.ErrorCertStatusRevoked}
}

func (c *Client) validateCertificateOCSP(ctx context.Context, req ValidateCertificateRequest, input []byte, endpoint string, flags ckalkan.Flag) (*CertificateValidation, error) {
	certificate, err := parseOCSPCertificate(input)
	if err != nil {
		return nil, fmt.Errorf("%w: parse OCSP certificate: %w", ErrInvalidInput, err)
	}

	var issuer *x509.Certificate

	if !req.Issuer.isZero() {
		issuerInput, err := certificateValidationInput(req.Issuer, c.configuredMaxInputSize())
		if err != nil {
			return nil, fmt.Errorf("kalkan: OCSP issuer: %w", err)
		}

		issuer, err = parseOCSPCertificate(issuerInput)
		if err != nil {
			return nil, fmt.Errorf("%w: parse OCSP issuer: %w", ErrInvalidInput, err)
		}

		if err := checkOCSPIssuer(certificate, issuer); err != nil {
			return nil, fmt.Errorf("%w: OCSP issuer: %w", ErrInvalidInput, err)
		}
	}

	var (
		trusted       []loadedTrustedCertificate
		checkTimeUnix int64
	)
	if !req.CheckTime.IsZero() {
		checkTimeUnix = req.CheckTime.Unix()
	}

	// Retain native chain and certificate-time validation.
	// Do not invoke the vendor's OCSP transport.
	// Copy trust state under the native call gate.
	result, err := withLockedLibraryResult(c, ctx, "ValidateCertificate", func(native certificates) (ckalkan.ValidateCertificateResult, error) {
		if issuer == nil {
			trusted = slices.Clone(c.trusted)
		}

		return native.X509ValidateCertificate(ckalkan.ValidateCertificateRequest{
			Certificate: input, ValidationType: ckalkan.UseNothing,
			CheckTimeUnix: checkTimeUnix, Flags: flags,
		})
	})
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if issuer == nil {
		issuer = findOCSPIssuer(certificate, trusted)
		if issuer == nil {
			return nil, fmt.Errorf("%w: OCSP issuer not found in loaded certificates; supply Issuer", ErrInvalidInput)
		}
	}

	id, err := kalkanOCSPCertID(certificate.SerialNumber, issuer)
	if err != nil {
		return nil, fmt.Errorf("kalkan: build OCSP certificate ID: %w", err)
	}

	request, err := kalkanOCSPRequest(id)
	if err != nil {
		return nil, fmt.Errorf("kalkan: encode OCSP request: %w", err)
	}

	answer, err := c.fetchOCSP(ctx, endpoint, request)
	if err != nil {
		return nil, err
	}

	revokedAt, revoked, err := kalkanOCSPStatus(answer, id, issuer, time.Now())
	if err != nil {
		return nil, fmt.Errorf("kalkan: verify OCSP response: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if revoked {
		return nil, &OCSPRevokedError{Endpoint: endpoint, RevokedAt: revokedAt}
	}

	validation := &CertificateValidation{Info: result.Info}
	if req.ReturnOCSPResponse {
		validation.OCSPResponse = answer
	}

	return validation, nil
}

func checkOCSPIssuer(certificate, issuer *x509.Certificate) error {
	if !bytes.Equal(certificate.RawIssuer, issuer.RawSubject) ||
		len(certificate.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 && !bytes.Equal(certificate.AuthorityKeyId, issuer.SubjectKeyId) {
		return errors.New("certificate is issued by another CA")
	}

	return certsig.CheckCertificateSignature(certificate, issuer)
}

func findOCSPIssuer(certificate *x509.Certificate, trusted []loadedTrustedCertificate) *x509.Certificate {
	for _, candidate := range trusted {
		data, err := ocspTrustedCertificateBytes(candidate)
		if err != nil {
			continue
		}

		issuer, err := parseOCSPCertificate(data)
		if err == nil && checkOCSPIssuer(certificate, issuer) == nil {
			return issuer
		}
	}

	return nil
}

func ocspTrustedCertificateBytes(certificate loadedTrustedCertificate) ([]byte, error) {
	if certificate.path == "" {
		return certificate.data, nil
	}

	// A trust file is normally a few kilobytes.
	// Bound file reads during issuer lookup outside the native trust store.
	// Reject special files.
	info, err := os.Stat(certificate.path)
	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() || info.Size() > kalkanOCSPMaxResponseBytes {
		return nil, fmt.Errorf("OCSP issuer must be a regular certificate file of at most %d bytes", kalkanOCSPMaxResponseBytes)
	}

	file, err := os.Open(certificate.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, kalkanOCSPMaxResponseBytes+1))
	if err != nil {
		return nil, err
	}

	if len(data) > kalkanOCSPMaxResponseBytes {
		return nil, fmt.Errorf("OCSP issuer file exceeds %d bytes", kalkanOCSPMaxResponseBytes)
	}

	return data, nil
}

func parseOCSPCertificate(data []byte) (*x509.Certificate, error) {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		der, err := parseCertificatePEM(data)
		if err != nil {
			return nil, err
		}

		return parseOCSPDERCertificate(der)
	}

	certificate, err := parseOCSPDERCertificate(data)
	if err == nil {
		return certificate, nil
	}

	der, decodeErr := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data)))
	if decodeErr != nil {
		return nil, err
	}

	return parseOCSPDERCertificate(der)
}

func (c *Client) fetchOCSP(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	timeout := c.config.ocspTimeout
	if timeout == 0 {
		timeout = DefaultOCSPTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	c.mu.Lock()
	proxy := c.config.proxy
	c.mu.Unlock()

	if proxy.Enabled {
		// Proxy validation permits a leading plus, but URL ports contain digits only.
		port := strings.TrimPrefix(strings.TrimSpace(proxy.Port), "+")
		address := &url.URL{Scheme: "http", Host: net.JoinHostPort(strings.Trim(strings.TrimSpace(proxy.Address), "[]"), port)}

		if proxy.User != "" || proxy.Password != "" {
			address.User = url.UserPassword(proxy.User, proxy.Password)
		}

		transport.Proxy = http.ProxyURL(address)
	}

	client := &http.Client{
		Transport: transport,
		// Redirects can change POST into GET or escape the endpoint policy.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kalkan: create OCSP request: %w", err)
	}

	request.Header.Set("Content-Type", "application/ocsp-request")
	request.Header.Set("Accept", "application/ocsp-response")

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("kalkan: request OCSP response: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kalkan: OCSP HTTP status %d", response.StatusCode)
	}

	answer, err := io.ReadAll(io.LimitReader(response.Body, kalkanOCSPMaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("kalkan: read OCSP response: %w", err)
	}

	if len(answer) > kalkanOCSPMaxResponseBytes {
		return nil, fmt.Errorf("kalkan: OCSP response exceeds %d bytes", kalkanOCSPMaxResponseBytes)
	}

	return answer, nil
}
