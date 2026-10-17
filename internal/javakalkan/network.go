package javakalkan

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

const maxEvidenceSize int64 = 64 << 20

var (
	errEndpoint     = errors.New("endpoint rejected")
	errEvidenceSize = errors.New("input exceeds size limit")
	errHTTPStatus   = errors.New("HTTP response is not successful")
)

func safeFetchError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, errEndpoint):
		return "endpoint rejected by URL policy (redirects are disabled)"
	case errors.Is(err, errEvidenceSize):
		return errEvidenceSize.Error()
	case errors.Is(err, errHTTPStatus):
		return errHTTPStatus.Error()
	default:
		return "network failure"
	}
}

func (c *Operation) evidenceLimit() int64 {
	if c.cfg.MaxInputSize > 0 {
		return min(c.cfg.MaxInputSize, maxEvidenceSize)
	}

	return maxEvidenceSize
}

func (c *Operation) validationURL(raw string) (string, error) {
	if c.cfg.ValidateURL != nil {
		var err error

		raw, err = c.cfg.ValidateURL(raw)
		if err != nil {
			return "", errors.Join(errEndpoint, err)
		}
	}

	return parseHTTPURL(raw)
}

func parseHTTPURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", errEndpoint
	}

	return raw, nil
}

// Network access stays in Go so operation cancellation and the caller's URL
// policy also apply to endpoints extracted from untrusted certificates. Each
// request has a 15-second deadline and a bounded decoded response. Redirects
// are rejected; ambient HTTP proxy environment variables are not used.
func (c *Operation) fetch(method, rawURL string, body []byte) ([]byte, error) {
	timestamp := method == "TSP"
	if timestamp {
		method = http.MethodPost
	}

	if (method != http.MethodGet && method != http.MethodPost) || (method == http.MethodGet && len(body) != 0) {
		return nil, errEndpoint
	}

	endpoint, err := c.validationURL(rawURL)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errEndpoint
	}

	switch {
	case timestamp:
		req.Header.Set("Content-Type", "application/timestamp-query")
		req.Header.Set("Accept", "application/timestamp-reply")
	case method == http.MethodPost:
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")
	default:
		req.Header.Set("Accept", "application/pkix-crl, application/x-pkcs7-crl, */*")
	}

	transport := &http.Transport{
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
		DisableKeepAlives:      true,
	}
	if c.proxyURL != nil {
		transport.Proxy = http.ProxyURL(c.proxyURL)
	}
	defer transport.CloseIdleConnections()

	httpClient := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errEndpoint },
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errHTTPStatus
	}

	limit := c.evidenceLimit()

	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(data)) > limit {
		return nil, errEvidenceSize
	}

	return data, nil
}

func (c *Operation) configureProxy(req ckalkan.ProxyRequest) error {
	if req.Flags&ckalkan.ProxyOn == 0 {
		c.proxyURL = nil
		return nil
	}

	port, err := strconv.Atoi(req.Port)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%w: proxy port", ErrInvalidInput)
	}

	if req.Address == "" || strings.ContainsAny(req.Address, "/@?# \t\r\n") {
		return fmt.Errorf("%w: proxy address", ErrInvalidInput)
	}

	proxy := &url.URL{Scheme: "http", Host: net.JoinHostPort(strings.Trim(req.Address, "[]"), req.Port)}
	if req.Flags&ckalkan.ProxyAuth != 0 {
		proxy.User = url.UserPassword(req.User, req.Password)
	}

	c.proxyURL = proxy

	return nil
}

func (c *Operation) revocationSource(mode, source string) (string, []byte, error) {
	if source == "" || mode == "none" {
		return source, nil, nil
	}

	if mode == "ocsp" || strings.Contains(source, "://") {
		// Only syntax is checked when configuring the backend. The destination
		// policy is enforced by fetch, when an operation actually uses the URL.
		endpoint, err := parseHTTPURL(source)
		return endpoint, nil, err
	}

	info, err := os.Stat(source)
	if err != nil {
		return "", nil, fmt.Errorf("CRL source: %w", err)
	}

	paths := []string{source}
	if info.IsDir() {
		entries, err := os.ReadDir(source)
		if err != nil {
			return "", nil, err
		}

		paths = nil

		for _, entry := range entries {
			if !entry.IsDir() {
				ext := strings.ToLower(filepath.Ext(entry.Name()))
				if ext == ".crl" || ext == ".pem" || ext == ".der" {
					paths = append(paths, filepath.Join(source, entry.Name()))
				}
			}
		}
	}

	if len(paths) == 0 || len(paths) > 256 {
		return "", nil, fmt.Errorf("%w: CRL source requires 1..256 CRL files", ErrInvalidInput)
	}

	var bundle []byte

	for _, path := range paths {
		data, err := c.readEvidenceFile(path)
		if err != nil {
			return "", nil, err
		}

		if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
			data = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: data})
		}

		if int64(len(bundle))+int64(len(data))+1 > c.evidenceLimit() {
			return "", nil, errEvidenceSize
		}

		bundle = append(bundle, data...)
		bundle = append(bundle, '\n')
	}

	return "", bundle, nil
}
