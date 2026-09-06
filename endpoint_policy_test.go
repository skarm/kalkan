package kalkan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestEndpointPolicyAllowsExactConfiguredEndpoints(t *testing.T) {
	policy := EndpointPolicy{
		AllowedHosts: []string{"tsp.pki.gov.kz", "ocsp.pki.gov.kz"},
		AllowedPorts: []string{"80"},
	}
	cfg := defaultOpenConfig()
	WithLibraryPath(testLibraryPath())(&cfg)
	WithEndpointPolicy(policy)(&cfg)

	if err := cfg.validate(); err != nil {
		t.Fatalf("config validation returned error: %v", err)
	}
}

func TestEndpointPolicyRejectsUnsafeEndpointShapes(t *testing.T) {
	policy := EndpointPolicy{
		AllowedHosts: []string{"trusted.example"},
		AllowedPorts: []string{"443"},
		RequireHTTPS: true,
	}

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "HTTP downgrade", value: "http://trusted.example/path", want: "must use https"},
		{name: "unlisted host", value: "https://internal.example/path", want: "not in the endpoint allowlist"},
		{name: "userinfo", value: "https://user:pass@trusted.example/path", want: "must not contain user information"},
		{name: "fragment", value: "https://trusted.example/path#fragment", want: "must not contain a fragment"},
		{name: "unlisted port", value: "https://trusted.example:8443/path", want: "port"},
		{name: "IP literal", value: "https://127.0.0.1/path", want: "IP address destinations are not allowed"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeNativeHTTPURLWithPolicy("TSA URL", test.value, endpointPurposeTSA, &policy)
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want ErrInvalidInput containing %q", err, test.want)
			}
		})
	}
}

func TestEndpointPolicyAddressForms(t *testing.T) {
	for _, test := range []struct {
		name       string
		host       string
		value      string
		allowIP    bool
		wantURL    string
		wantReason string
	}{
		{name: "IPv4", host: "127.0.0.1", value: "https://127.0.0.1:8443/path", allowIP: true, wantURL: "https://127.0.0.1:8443/path"},
		{name: "IPv6", host: "2001:db8::1", value: "https://[2001:db8::1]:8443/path", allowIP: true, wantURL: "https://[2001:db8::1]:8443/path"},
		{name: "IPv6 without permission", host: "2001:db8::1", value: "https://[2001:db8::1]:8443/path", wantReason: "IP address destinations are not allowed"},
		{name: "unlisted IPv6", host: "2001:db8::1", value: "https://[2001:db8::2]:8443/path", allowIP: true, wantReason: "not in the endpoint allowlist"},
		{name: "IPv6 zone", host: "2001:db8::1", value: "https://[2001:db8::1%25eth0]:8443/path", allowIP: true, wantReason: "IPv6 zone identifiers are not allowed"},
		{name: "Punycode", host: "xn--bcher-kva.example", value: " https://XN--BCHER-KVA.example:8443/path ", wantURL: "https://XN--BCHER-KVA.example:8443/path"},
		{name: "Unicode URL host", host: "xn--bcher-kva.example", value: "https://bücher.example:8443/path", wantReason: "must use an ASCII DNS form"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := EndpointPolicy{
				AllowedHosts:     []string{test.host},
				AllowedPorts:     []string{"8443"},
				RequireHTTPS:     true,
				AllowIPAddresses: test.allowIP,
			}
			got, err := normalizeNativeHTTPURLWithPolicy("TSA URL", test.value, endpointPurposeTSA, &policy)
			if test.wantReason != "" {
				if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), test.wantReason) {
					t.Fatalf("validation error = %v, want ErrInvalidInput containing %q", err, test.wantReason)
				}
				return
			}
			if err != nil || got != test.wantURL {
				t.Fatalf("normalized URL = %q, error = %v, want %q", got, err, test.wantURL)
			}
			if err := policy.validate(); err != nil {
				t.Fatalf("policy configuration rejected an accepted address form: %v", err)
			}
		})
	}
}

func TestEndpointPolicyAppliesToPerRequestOCSPOverride(t *testing.T) {
	native := &fakeNative{
		validateCertificateFunc: func(ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			t.Fatal("ValidateCertificate called native for an endpoint rejected by policy")
			return ckalkan.ValidateCertificateResult{}, nil
		},
	}
	client := &Client{
		library: native,
		config: runtimeConfig{
			ocspURL: defaultOCSPURL,
			endpointPolicy: &EndpointPolicy{
				AllowedHosts: []string{"ocsp.pki.gov.kz"},
				AllowedPorts: []string{"80"},
			},
		},
	}

	_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate:      DER([]byte{1, 2, 3}),
		Mode:             CertificateValidationOCSP,
		RevocationSource: "http://127.0.0.1/ocsp",
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "IP address destinations are not allowed") {
		t.Fatalf("ValidateCertificate error = %v, want endpoint policy rejection", err)
	}
}

func TestEndpointPolicyOptionClonesAllowlist(t *testing.T) {
	hosts := []string{"tsp.pki.gov.kz", "ocsp.pki.gov.kz"}
	ports := []string{"80"}
	policy := EndpointPolicy{AllowedHosts: hosts, AllowedPorts: ports}
	option := WithEndpointPolicy(policy)
	hosts[0] = "attacker.invalid"
	ports[0] = "9999"
	cfg := defaultOpenConfig()
	option(&cfg)

	if got := cfg.endpointPolicy.AllowedHosts[0]; got != "tsp.pki.gov.kz" {
		t.Fatalf("stored endpoint host = %q, want cloned original", got)
	}
	if got := cfg.endpointPolicy.AllowedPorts[0]; got != "80" {
		t.Fatalf("stored endpoint port = %q, want cloned original", got)
	}
	runtimeConfig := cfg.runtime()
	cfg.endpointPolicy.AllowedHosts[0] = "changed.invalid"
	cfg.endpointPolicy.AllowedPorts[0] = "1234"
	if runtimeConfig.endpointPolicy.AllowedHosts[0] != "tsp.pki.gov.kz" || runtimeConfig.endpointPolicy.AllowedPorts[0] != "80" {
		t.Fatal("runtime policy shares mutable configuration slices")
	}
	option(&cfg)
	if cfg.endpointPolicy.AllowedHosts[0] != "tsp.pki.gov.kz" || cfg.endpointPolicy.AllowedPorts[0] != "80" {
		t.Fatal("reused option shares mutable configuration slices")
	}
}

func TestEndpointPolicyRejectsInvalidConfigurationBeforeNative(t *testing.T) {
	for _, test := range []struct {
		name    string
		policy  EndpointPolicy
		tsaURL  string
		ocspURL string
		want    string
	}{
		{name: "no hosts", want: "requires at least one allowed host"},
		{name: "empty host", policy: EndpointPolicy{AllowedHosts: []string{""}}, want: "host is empty"},
		{name: "URL as host", policy: EndpointPolicy{AllowedHosts: []string{"https://example.com"}}, want: "must not include URL syntax"},
		{name: "IP not enabled", policy: EndpointPolicy{AllowedHosts: []string{"127.0.0.1"}}, want: "AllowIPAddresses is false"},
		{name: "IPv6 not enabled", policy: EndpointPolicy{AllowedHosts: []string{"2001:db8::1"}}, want: "AllowIPAddresses is false"},
		{name: "bracketed IPv6 host", policy: EndpointPolicy{AllowedHosts: []string{"[2001:db8::1]"}, AllowIPAddresses: true}, want: "must not include URL syntax"},
		{name: "Unicode host", policy: EndpointPolicy{AllowedHosts: []string{"bücher.example"}}, want: "must use an ASCII DNS form"},
		{name: "invalid port", policy: EndpointPolicy{AllowedHosts: []string{"example.com"}, AllowedPorts: []string{"65536"}}, want: "must be in range 1..65535"},
		{name: "TSA override", policy: EndpointPolicy{AllowedHosts: []string{"tsp.pki.gov.kz", "ocsp.pki.gov.kz"}}, tsaURL: "https://outside.example", want: "not in the endpoint allowlist"},
		{name: "OCSP override", policy: EndpointPolicy{AllowedHosts: []string{"tsp.pki.gov.kz", "ocsp.pki.gov.kz"}}, ocspURL: "https://outside.example", want: "not in the endpoint allowlist"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := []Option{WithLibraryPath(testLibraryPath()), WithEndpointPolicy(test.policy)}
			if test.tsaURL != "" {
				options = append(options, WithTSAURL(test.tsaURL))
			}
			if test.ocspURL != "" {
				options = append(options, WithOCSPURL(test.ocspURL))
			}
			called := false
			client, err := openWithLibraryFactory(context.Background(), options, func(config) (closer, error) { called = true; return &fakeNative{}, nil })
			if client != nil {
				defer client.Close()
			}
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), test.want) || called {
				t.Fatalf("Open error = %v, factory called = %t, want ErrInvalidInput containing %q before native", err, called, test.want)
			}
		})
	}
}

func TestEndpointPolicyKeepsUnrestrictedDefault(t *testing.T) {
	cfg := defaultOpenConfig()
	WithLibraryPath(testLibraryPath())(&cfg)
	WithTSAURL("https://custom-tsa.example")(&cfg)
	WithOCSPURL("http://custom-ocsp.example:8080")(&cfg)
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.endpointPolicy != nil || cfg.runtime().endpointPolicy != nil {
		t.Fatal("default endpoint policy is restricted")
	}
}

func TestEndpointPolicyOpenAndOCSPOverride(t *testing.T) {
	var tsa string
	var responder string
	native := &fakeNative{
		setTSAURLFunc: func(url string) error { tsa = url; return nil },
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			responder = req.ValidationPath
			return ckalkan.ValidateCertificateResult{Info: "ok"}, nil
		},
	}
	client, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath(testLibraryPath()),
		WithTSAURL("https://TSA.EXAMPLE./timestamp"),
		WithOCSPURL("https://ocsp.example"),
		WithEndpointPolicy(EndpointPolicy{AllowedHosts: []string{"tsa.example", "ocsp.example"}, RequireHTTPS: true}),
	}, func(config) (closer, error) { return native, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if tsa != "https://TSA.EXAMPLE./timestamp" {
		t.Fatalf("TSA URL = %q", tsa)
	}
	_, err = client.ValidateCertificate(context.Background(), ValidateCertificateRequest{Certificate: DER([]byte{1, 2, 3}), Mode: CertificateValidationOCSP, RevocationSource: "https://OCSP.EXAMPLE.:443/check"})
	if err != nil {
		t.Fatal(err)
	}
	if responder != "https://OCSP.EXAMPLE.:443/check" {
		t.Fatalf("OCSP URL = %q", responder)
	}
	_, err = client.ValidateCertificate(context.Background(), ValidateCertificateRequest{Certificate: DER([]byte{1, 2, 3}), Mode: CertificateValidationOCSP, RevocationSource: "https://ocsp.example:8443/check"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-default port error = %v", err)
	}
	if responder != "https://OCSP.EXAMPLE.:443/check" {
		t.Fatalf("rejected OCSP URL reached native: %q", responder)
	}
}
