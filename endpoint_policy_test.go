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

func TestEndpointPolicyCanExplicitlyAllowIPAddress(t *testing.T) {
	policy := EndpointPolicy{
		AllowedHosts:     []string{"127.0.0.1"},
		AllowedPorts:     []string{"8443"},
		RequireHTTPS:     true,
		AllowIPAddresses: true,
	}

	got, err := normalizeNativeHTTPURLWithPolicy("TSA URL", "https://127.0.0.1:8443/path", endpointPurposeTSA, &policy)
	if err != nil {
		t.Fatalf("validation returned error: %v", err)
	}
	if got != "https://127.0.0.1:8443/path" {
		t.Fatalf("normalized URL = %q", got)
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
	}{
		{name: "no hosts"},
		{name: "empty host", policy: EndpointPolicy{AllowedHosts: []string{""}}},
		{name: "URL as host", policy: EndpointPolicy{AllowedHosts: []string{"https://example.com"}}},
		{name: "IP not enabled", policy: EndpointPolicy{AllowedHosts: []string{"127.0.0.1"}}},
		{name: "invalid port", policy: EndpointPolicy{AllowedHosts: []string{"example.com"}, AllowedPorts: []string{"65536"}}},
		{name: "TSA override", policy: EndpointPolicy{AllowedHosts: []string{"tsp.pki.gov.kz", "ocsp.pki.gov.kz"}}, tsaURL: "https://outside.example"},
		{name: "OCSP override", policy: EndpointPolicy{AllowedHosts: []string{"tsp.pki.gov.kz", "ocsp.pki.gov.kz"}}, ocspURL: "https://outside.example"},
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
			if !errors.Is(err, ErrInvalidInput) || called {
				t.Fatalf("Open error = %v, factory called = %t", err, called)
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
