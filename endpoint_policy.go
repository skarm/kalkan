package kalkan

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// endpointPurpose identifies the network operation that will use an
// endpoint. It is provided to diagnostics so applications can distinguish TSA
// and OCSP policy failures.
type endpointPurpose string

const (
	// endpointPurposeTSA identifies the timestamp authority configured for
	// signing operations.
	endpointPurposeTSA endpointPurpose = "TSA"
	// endpointPurposeOCSP identifies an OCSP responder used for certificate
	// validation.
	endpointPurposeOCSP endpointPurpose = "OCSP"
)

// EndpointPolicy restricts native TSA/OCSP and Java revocation destinations.
// Its zero value is invalid: AllowedHosts must contain at least one host.
// Host matching is exact and case-insensitive after removing a trailing DNS dot.
// The policy is a local validation boundary: native KalkanCrypt performs DNS resolution and HTTP
// requests itself, so production deployments still need an egress firewall or
// proxy to prevent DNS rebinding and redirect-based bypasses. The Java backend
// validates each destination, including certificate-derived CRL URLs, and
// rejects redirects; DNS resolution still requires external egress controls.
type EndpointPolicy struct {
	// AllowedHosts is the exact allowlist of DNS names. IP literals are rejected
	// unless AllowIPAddresses is true and the literal is explicitly listed.
	// DNS names here and in endpoint URLs must use ASCII; use Punycode for
	// internationalized names. Unicode names are rejected without IDNA conversion.
	// List IPv6 literals without brackets, for example "2001:db8::1"; endpoint
	// URLs use brackets, for example "https://[2001:db8::1]/". IPv6 zone
	// identifiers are not supported.
	AllowedHosts []string
	// AllowedPorts contains allowed effective ports. When empty, only the
	// scheme-default port is accepted (80 for HTTP and 443 for HTTPS).
	AllowedPorts []string
	// RequireHTTPS rejects HTTP endpoints.
	RequireHTTPS bool
	// AllowIPAddresses permits explicitly allowlisted IPv4 or IPv6 literals.
	AllowIPAddresses bool
}

func (p EndpointPolicy) clone() *EndpointPolicy {
	p.AllowedHosts = slices.Clone(p.AllowedHosts)
	p.AllowedPorts = slices.Clone(p.AllowedPorts)

	return &p
}

func (p EndpointPolicy) validate() error {
	if len(p.AllowedHosts) == 0 {
		return fmt.Errorf("%w: endpoint policy requires at least one allowed host", ErrInvalidInput)
	}

	for _, rawHost := range p.AllowedHosts {
		host, err := normalizePolicyHost(rawHost)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidInput, err)
		}

		if ip := net.ParseIP(host); ip != nil && !p.AllowIPAddresses {
			return fmt.Errorf("%w: endpoint policy host %q is an IP address but AllowIPAddresses is false", ErrInvalidInput, rawHost)
		}
	}

	for _, rawPort := range p.AllowedPorts {
		port := strings.TrimSpace(rawPort)
		if port == "" {
			return fmt.Errorf("%w: endpoint policy contains an empty allowed port", ErrInvalidInput)
		}

		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return fmt.Errorf("%w: endpoint policy port %q must be in range 1..65535", ErrInvalidInput, rawPort)
		}
	}

	return nil
}

func (p EndpointPolicy) validateEndpoint(field string, purpose endpointPurpose, endpoint *url.URL) error {
	if endpoint.User != nil {
		return fmt.Errorf("%w: %s must not contain user information", ErrInvalidInput, field)
	}

	if endpoint.Fragment != "" {
		return fmt.Errorf("%w: %s must not contain a fragment", ErrInvalidInput, field)
	}

	if p.RequireHTTPS && endpoint.Scheme != "https" {
		return fmt.Errorf("%w: %s must use https under the endpoint policy", ErrInvalidInput, field)
	}

	host, err := normalizePolicyHost(endpoint.Hostname())
	if err != nil {
		return fmt.Errorf("%w: %s host is not allowed: %w", ErrInvalidInput, field, err)
	}

	if strings.Contains(host, "%") {
		return fmt.Errorf("%w: %s IPv6 zone identifiers are not allowed", ErrInvalidInput, field)
	}

	if ip := net.ParseIP(host); ip != nil && !p.AllowIPAddresses {
		return fmt.Errorf("%w: %s IP address destinations are not allowed", ErrInvalidInput, field)
	}

	allowedHost := false

	for _, candidate := range p.AllowedHosts {
		normalized, normalizeErr := normalizePolicyHost(candidate)
		if normalizeErr == nil && normalized == host {
			allowedHost = true
			break
		}
	}

	if !allowedHost {
		return fmt.Errorf("%w: %s host %q is not in the endpoint allowlist for %s", ErrInvalidInput, field, host, purpose)
	}

	effectivePort := endpoint.Port()

	defaultPort := defaultHTTPPort(endpoint.Scheme)
	if effectivePort == "" {
		effectivePort = defaultPort
	}

	if len(p.AllowedPorts) == 0 {
		if effectivePort != defaultPort {
			return fmt.Errorf("%w: %s port %q is not the default for %s", ErrInvalidInput, field, effectivePort, endpoint.Scheme)
		}

		return nil
	}

	for _, allowedPort := range p.AllowedPorts {
		if strings.TrimSpace(allowedPort) == effectivePort {
			return nil
		}
	}

	return fmt.Errorf("%w: %s port %q is not in the endpoint allowlist", ErrInvalidInput, field, effectivePort)
}

func normalizePolicyHost(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if host == "" {
		return "", errors.New("endpoint policy host is empty")
	}

	if strings.ContainsFunc(host, unicode.IsSpace) {
		return "", fmt.Errorf("endpoint policy host %q contains whitespace", value)
	}

	if strings.ContainsAny(host, "/@?#[]") {
		return "", fmt.Errorf("endpoint policy host %q must not include URL syntax", value)
	}

	for _, r := range host {
		if r > unicode.MaxASCII {
			return "", fmt.Errorf("endpoint policy host %q must use an ASCII DNS form", value)
		}
	}

	return host, nil
}

func defaultHTTPPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}

	return "80"
}
