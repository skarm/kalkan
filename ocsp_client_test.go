package kalkan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/internal/certsig"
)

func ocspTestClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	cfg := defaultOpenConfig()
	WithOCSPURL(endpoint)(&cfg)
	WithCustomOCSP()(&cfg)
	return &Client{config: cfg.runtime(), library: &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			if req.ValidationType != ckalkan.UseNothing || req.ValidationPath != "" || req.Flags&ckalkan.GetOCSPResponse != 0 {
				t.Errorf("OCSP reached vendor: %+v", req)
			}
			return ckalkan.ValidateCertificateResult{Info: "chain ok"}, nil
		},
		loadCertBufferFunc: func([]byte, ckalkan.CertFormat) error { return nil },
		loadCertFileFunc:   func(string, ckalkan.CertType) error { return nil },
		setProxyFunc:       func(ckalkan.ProxyRequest) error { return nil },
	}}
}

func TestValidateCertificateOCSP(t *testing.T) {
	pki := newTestOCSPPKI(t)
	now := time.Now()
	answer := pki.answer(t, pki.responder, testOCSPResponse{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)})
	wantRequest, _ := kalkanOCSPRequest(pki.certID(t))
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/ocsp-request" || r.Header.Get("Accept") != "application/ocsp-response" {
			t.Error("invalid OCSP HTTP request")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, wantRequest) {
			t.Error("wrong OCSP CertID")
		}
		_, _ = w.Write(answer)
	}))
	defer server.Close()
	for _, source := range []Source{DER(pki.leaf.Raw), PEM(encodeCertificatePEM(pki.leaf.Raw)), Base64([]byte(base64.StdEncoding.EncodeToString(pki.leaf.Raw))), Bytes(pki.leaf.Raw)} {
		client := ocspTestClient(t, server.URL)
		for _, returnResponse := range []bool{false, true} {
			result, err := client.ValidateCertificate(t.Context(), ValidateCertificateRequest{Certificate: source, Issuer: DER(pki.ca.Raw), Mode: CertificateValidationOCSP, ReturnOCSPResponse: returnResponse})
			if err != nil {
				t.Fatal(err)
			}
			if result.Info != "chain ok" || returnResponse && !bytes.Equal(result.OCSPResponse, answer) || !returnResponse && result.OCSPResponse != nil {
				t.Fatalf("result=%+v", result)
			}
		}
	}
	if hits.Load() != 8 {
		t.Fatalf("HTTP requests=%d", hits.Load())
	}
}

func TestCustomOCSPEndpointPolicy(t *testing.T) {
	pki := newTestOCSPPKI(t)
	now := time.Now()
	answer := pki.answer(t, pki.responder, testOCSPResponse{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)})
	var hits atomic.Int32
	paths := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		paths <- r.URL.Path
		_, _ = w.Write(answer)
	}))
	defer server.Close()
	var forbiddenHits atomic.Int32
	forbiddenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forbiddenHits.Add(1)
		_, _ = w.Write(answer)
	}))
	defer forbiddenServer.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	nativeCalls := 0
	client, err := openWithLibraryFactory(t.Context(), []Option{
		WithLibraryPath(testLibraryPath()),
		WithTSAURL(server.URL),
		WithOCSPURL(server.URL + "/configured"),
		WithCustomOCSP(),
		WithEndpointPolicy(EndpointPolicy{
			AllowedHosts:     []string{endpoint.Hostname()},
			AllowedPorts:     []string{endpoint.Port()},
			AllowIPAddresses: true,
		}),
	}, func(config) (closer, error) {
		return &fakeNative{
			validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
				nativeCalls++
				if req.ValidationType != ckalkan.UseNothing || req.ValidationPath != "" || req.Flags&ckalkan.GetOCSPResponse != 0 {
					t.Errorf("OCSP reached vendor: %+v", req)
				}
				return ckalkan.ValidateCertificateResult{Info: "chain ok"}, nil
			},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, test := range []struct {
		name     string
		endpoint string
		path     string
		allowed  bool
	}{
		{name: "forbidden host", endpoint: "http://localhost:" + endpoint.Port() + "/forbidden"},
		{name: "forbidden port", endpoint: forbiddenServer.URL + "/forbidden"},
		{name: "configured endpoint", path: "/configured", allowed: true},
		{name: "per-request endpoint", endpoint: server.URL + "/per-request", path: "/per-request", allowed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			beforeNative, beforeHTTP := nativeCalls, hits.Load()
			result, err := client.ValidateCertificate(t.Context(), ValidateCertificateRequest{
				Certificate: DER(pki.leaf.Raw), Issuer: DER(pki.ca.Raw),
				Mode: CertificateValidationOCSP, RevocationSource: test.endpoint, ReturnOCSPResponse: true,
			})
			if !test.allowed {
				if !errors.Is(err, ErrInvalidInput) || result != nil {
					t.Fatalf("forbidden endpoint result=%+v, error=%v; want ErrInvalidInput", result, err)
				}
				if nativeCalls != beforeNative || hits.Load() != beforeHTTP || forbiddenHits.Load() != 0 {
					t.Fatalf("forbidden endpoint reached native or HTTP: native=%d, HTTP=%d, forbidden HTTP=%d", nativeCalls-beforeNative, hits.Load()-beforeHTTP, forbiddenHits.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Info != "chain ok" || !bytes.Equal(result.OCSPResponse, answer) {
				t.Fatalf("OCSP result=%+v", result)
			}
			if nativeCalls != beforeNative+1 || hits.Load() != beforeHTTP+1 || forbiddenHits.Load() != 0 {
				t.Fatalf("allowed endpoint calls: native=%d, HTTP=%d, forbidden HTTP=%d", nativeCalls-beforeNative, hits.Load()-beforeHTTP, forbiddenHits.Load())
			}
			if path := <-paths; path != test.path {
				t.Fatalf("OCSP path=%q, want %q", path, test.path)
			}
		})
	}
}

func TestOCSPTrustedIssuerAndNativeValidation(t *testing.T) {
	pki := newTestOCSPPKI(t)
	answer := pki.answer(t, nil, testOCSPResponse{ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(answer) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "issuer.pem")
	if err := os.WriteFile(path, encodeCertificatePEM(pki.ca.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, trust := range []TrustedCertificate{
		{Data: pki.ca.Raw, Format: CertificateDER},
		{Data: encodeCertificatePEM(pki.ca.Raw), Format: CertificatePEM},
		{Data: []byte(base64.StdEncoding.EncodeToString(pki.ca.Raw)), Format: CertificateBase64},
		{Path: path},
	} {
		client := ocspTestClient(t, server.URL)
		if err := client.LoadTrustedCertificate(t.Context(), trust); err != nil {
			t.Fatal(err)
		}
		req := ValidateCertificateRequest{Certificate: DER(pki.leaf.Raw), Mode: CertificateValidationOCSP}
		if _, err := client.ValidateCertificate(t.Context(), req); err != nil {
			t.Fatal(err)
		}
	}
	client := ocspTestClient(t, server.URL)
	req := ValidateCertificateRequest{Certificate: DER(pki.leaf.Raw), Mode: CertificateValidationOCSP}
	if _, err := client.ValidateCertificate(t.Context(), req); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "Issuer") {
		t.Fatalf("missing issuer=%v", err)
	}
	req.Issuer = DER(pki.ca.Raw)
	req.CheckTime = time.Unix(1700000000, 0)
	req.CertificateTimeCheck = SkipCertificateTimeCheck
	nativeErr := errors.New("untrusted chain")
	ocspTestNative(t, client).validateCertificateFunc = func(native ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
		if native.ValidationType != ckalkan.UseNothing || native.Flags != ckalkan.NoCheckCertTime || native.CheckTimeUnix != req.CheckTime.Unix() {
			t.Errorf("native request=%+v", native)
		}
		return ckalkan.ValidateCertificateResult{}, nativeErr
	}
	if _, err := client.ValidateCertificate(t.Context(), req); !errors.Is(err, nativeErr) {
		t.Fatalf("native chain failure=%v", err)
	}
}

func TestOCSPRejectsRevokedAndInvalidResponses(t *testing.T) {
	pki := newTestOCSPPKI(t)
	now := time.Now()
	good := testOCSPResponse{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	revoked := good
	revoked.Status = testOCSPRevoked
	revoked.RevokedAt = now.Add(-time.Hour).Truncate(time.Second)
	bad := pki.answer(t, nil, good)
	bad[len(bad)-1] ^= 1
	for _, test := range []struct {
		name    string
		status  int
		body    []byte
		revoked bool
	}{
		{"revoked", 200, pki.answer(t, nil, revoked), true},
		{"bad signature", 200, bad, false},
		{"too large", 200, bytes.Repeat([]byte{0}, kalkanOCSPMaxResponseBytes+1), false},
		{"HTTP failure", 503, nil, false},
		{"redirect", 307, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Location", "/redirect")
				w.WriteHeader(test.status)
				_, _ = w.Write(test.body)
			}))
			defer server.Close()
			client := ocspTestClient(t, server.URL)
			result, err := client.ValidateCertificate(t.Context(), ValidateCertificateRequest{Certificate: DER(pki.leaf.Raw), Issuer: DER(pki.ca.Raw), Mode: CertificateValidationOCSP})
			if err == nil || result != nil {
				t.Fatalf("invalid response accepted: %+v, %v", result, err)
			}
			if test.revoked {
				var rev *OCSPRevokedError
				if !errors.As(err, &rev) || !rev.RevokedAt.Equal(revoked.RevokedAt) || rev.Endpoint != server.URL {
					t.Fatalf("revocation=%v", err)
				}
				if code, ok := ckalkan.ErrorCodeOf(err); !ok || code != ckalkan.ErrorCertStatusRevoked {
					t.Fatalf("revocation native code=%v,%v", code, ok)
				}
			}
			if hits.Load() != 1 {
				t.Fatalf("retried/redirected request %d times", hits.Load())
			}
		})
	}
}

func TestOCSPTimeoutAndCancellationReleaseNativeGate(t *testing.T) {
	pki := newTestOCSPPKI(t)
	for _, bodyStall := range []bool{false, true} {
		for _, cancelCaller := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{false: "headers", true: "body"}[bodyStall], map[bool]string{false: "timeout", true: "cancel"}[cancelCaller]}, "/"), func(t *testing.T) {
				started := make(chan struct{})
				release := make(chan struct{})
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if bodyStall {
						w.WriteHeader(200)
						_ = http.NewResponseController(w).Flush()
					}
					close(started)
					select {
					case <-r.Context().Done():
					case <-release:
					}
				}))
				defer server.Close()
				defer close(release)
				client := ocspTestClient(t, server.URL)
				client.config.ocspTimeout = 200 * time.Millisecond
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				finished := make(chan error, 1)
				go func() {
					_, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{Certificate: DER(pki.leaf.Raw), Issuer: DER(pki.ca.Raw), Mode: CertificateValidationOCSP})
					finished <- err
				}()
				select {
				case <-started:
				case <-time.After(3 * time.Second):
					t.Fatal("OCSP request did not start")
				}
				gateCtx, gateCancel := context.WithTimeout(t.Context(), time.Second)
				defer gateCancel()
				if err := client.SetProxy(gateCtx, Proxy{}); err != nil {
					t.Fatalf("OCSP holds native gate: %v", err)
				}
				want := context.DeadlineExceeded
				if cancelCaller {
					cancel()
					want = context.Canceled
				}
				select {
				case err := <-finished:
					if !errors.Is(err, want) {
						t.Fatalf("OCSP error=%v, want %v", err, want)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("OCSP request hangs")
				}
			})
		}
	}
}

func TestOCSPProxyUpdates(t *testing.T) {
	pki := newTestOCSPPKI(t)
	answer := pki.answer(t, nil, testOCSPResponse{ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)})
	var hits atomic.Int32
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Host != "ocsp.invalid" || r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			t.Error("proxy destination or credentials lost")
		}
		_, _ = w.Write(answer)
	}))
	defer proxyServer.Close()
	u, _ := url.Parse(proxyServer.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	for _, test := range []struct{ name, port string }{
		{"decimal port", port},
		{"leading plus", "+" + port},
		{"leading zeros", "00" + port},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := hits.Load()
			proxy := Proxy{Enabled: true, Address: host, Port: test.port, User: "user", Password: "pass"}
			client := ocspTestClient(t, "http://ocsp.invalid/check")
			defer client.Close()
			native := ocspTestNative(t, client)
			native.setProxyFunc = func(req ckalkan.ProxyRequest) error {
				if req.Port != test.port {
					t.Fatalf("native proxy port=%q, want original %q", req.Port, test.port)
				}
				return nil
			}
			if err := client.SetProxy(t.Context(), proxy); err != nil {
				t.Fatal(err)
			}
			req := ValidateCertificateRequest{Certificate: DER(pki.leaf.Raw), Issuer: DER(pki.ca.Raw), Mode: CertificateValidationOCSP}
			if _, err := client.ValidateCertificate(t.Context(), req); err != nil {
				t.Fatal(err)
			}
			if client.config.proxy.Port != test.port {
				t.Fatalf("stored proxy port=%q, want original %q", client.config.proxy.Port, test.port)
			}
			native.setProxyFunc = func(ckalkan.ProxyRequest) error { return errors.New("native proxy failed") }
			if err := client.SetProxy(t.Context(), Proxy{}); err == nil {
				t.Fatal("expected native failure")
			}
			if _, err := client.ValidateCertificate(t.Context(), req); err != nil {
				t.Fatalf("failed SetProxy changed Go proxy: %v", err)
			}
			if got := hits.Load() - before; got != 2 {
				t.Fatalf("proxy requests=%d, want 2", got)
			}
		})
	}
}

func TestOCSPNegativeSerialPreservesSignature(t *testing.T) {
	pki := newTestOCSPPKI(t)
	der, tbs := ocspTestNegativeSerialCertificate(t, pki.leaf, pki.caKey)
	cert, err := parseOCSPDERCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.SerialNumber.Int64() != -1 || !bytes.Equal(cert.Raw, der) || !bytes.Equal(cert.RawTBSCertificate, tbs) {
		t.Fatal("negative serial or signed bytes changed")
	}
	if err := certsig.CheckCertificateSignature(cert, pki.ca); err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Log("runtime allows negative serials directly")
	}
}

func ocspTestNegativeSerialCertificate(t *testing.T, certificate *x509.Certificate, issuerKey *ecdsa.PrivateKey) ([]byte, []byte) {
	t.Helper()

	var outer struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(certificate.Raw, &outer); err != nil {
		t.Fatal(err)
	}
	var version, serial asn1.RawValue
	rest, _ := asn1.Unmarshal(outer.TBS.Bytes, &version)
	rest, _ = asn1.Unmarshal(rest, &serial)
	serial.Bytes = []byte{0xff}
	serial.FullBytes = nil
	outer.TBS.Bytes = bytes.Join([][]byte{version.FullBytes, ocspTestMarshal(t, serial), rest}, nil)
	outer.TBS.FullBytes = nil
	tbs := ocspTestMarshal(t, outer.TBS)
	hash := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, issuerKey, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	outer.Signature = asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}
	return ocspTestMarshal(t, outer), tbs
}

func ocspTestNative(t *testing.T, client *Client) *fakeNative {
	t.Helper()
	native, ok := client.library.(*fakeNative)
	if !ok {
		t.Fatal("unexpected test native type")
	}
	return native
}

func TestOCSPTimeoutDoesNotEnableGoImplementation(t *testing.T) {
	const endpoint = "http://ocsp.example.test"
	nativeCalls := 0
	client, err := openWithLibraryFactory(t.Context(), []Option{
		WithLibraryPath(testLibraryPath()), WithOCSPURL(endpoint), WithOCSPTimeout(time.Nanosecond),
	}, func(config) (closer, error) {
		return &fakeNative{
			setTSAURLFunc: func(string) error { return nil },
			validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
				nativeCalls++
				if req.ValidationType != ckalkan.UseOCSP || req.ValidationPath != endpoint || req.Flags != ckalkan.GetOCSPResponse {
					t.Fatalf("native OCSP request: %+v", req)
				}
				return ckalkan.ValidateCertificateResult{Info: "native OCSP", OCSPResponse: []byte("native response")}, nil
			},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.ValidateCertificate(t.Context(), ValidateCertificateRequest{
		Certificate: Bytes([]byte("native certificate input")), Mode: CertificateValidationOCSP, ReturnOCSPResponse: true,
	})
	if err != nil || result.Info != "native OCSP" || string(result.OCSPResponse) != "native response" || nativeCalls != 1 {
		t.Fatalf("default OCSP = %+v, %v; native calls=%d", result, err, nativeCalls)
	}
	_, err = client.ValidateCertificate(t.Context(), ValidateCertificateRequest{
		Certificate: Bytes([]byte("native certificate input")), Issuer: DER([]byte("issuer")), Mode: CertificateValidationOCSP,
	})
	if !errors.Is(err, ErrInvalidInput) || nativeCalls != 1 {
		t.Fatalf("Issuer without Go OCSP = %v, calls=%d", err, nativeCalls)
	}
}

func TestCustomOCSPOptionKeepsOtherValidationModesNative(t *testing.T) {
	for _, mode := range []CertificateValidationMode{CertificateValidationNone, CertificateValidationCRL} {
		client := ocspTestClient(t, "http://ocsp.example.test")
		req := ValidateCertificateRequest{Certificate: Bytes([]byte("native certificate input")), Mode: mode}
		if mode == CertificateValidationCRL {
			req.RevocationSource = "/example/crl"
		}
		calls := 0
		ocspTestNative(t, client).validateCertificateFunc = func(native ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			calls++
			want, err := mode.native()
			if err != nil || native.ValidationType != want || native.ValidationPath != req.RevocationSource {
				t.Fatalf("request = %+v", native)
			}
			return ckalkan.ValidateCertificateResult{Info: "native validation"}, nil
		}
		result, err := client.ValidateCertificate(t.Context(), req)
		if err != nil || result.Info != "native validation" || calls != 1 {
			t.Fatalf("mode %d = %+v, %v; calls=%d", mode, result, err, calls)
		}
	}
}

func TestValidateCertificateOCSPGOST2015Digest256(t *testing.T) {
	issuer := readTestCertificate(t, "testdata/ocsp/gost2015_256/gost256-ca.der")
	leaf := readTestCertificate(t, "testdata/ocsp/gost2015_256/gost256-leaf.der")
	answer := readGOST256OCSPFixture(t, "gost256-ocsp-delegated-good.der")
	id, err := kalkanOCSPCertID(leaf.SerialNumber, issuer)
	if err != nil {
		t.Fatal(err)
	}
	wantRequest, err := kalkanOCSPRequest(id)
	if err != nil {
		t.Fatal(err)
	}
	var response ocspResponse
	if _, err := asn1.Unmarshal(answer, &response); err != nil {
		t.Fatal(err)
	}
	var basic ocspBasicResponse
	if _, err := asn1.Unmarshal(response.Bytes.Response, &basic); err != nil {
		t.Fatal(err)
	}
	basic.Signature.Bytes = bytes.Clone(basic.Signature.Bytes)
	basic.Signature.Bytes[0] ^= 1
	response.Bytes.Response = ocspTestMarshal(t, basic)
	tampered := ocspTestMarshal(t, response)

	// SDK fixtures are valid from 2019 to 2050.
	// Their fixed signed response interval covers the HTTP client's real clock
	// and the status test's fixed 2030 clock.
	// Neither test requires the SDK or a private key.
	for _, test := range []struct {
		name  string
		body  []byte
		valid bool
	}{
		{name: "delegated good", body: answer, valid: true},
		{name: "altered response signature", body: tampered},
		{name: "responder without OCSP signing usage", body: readGOST256OCSPFixture(t, "gost256-ocsp-without-eku.der")},
		{name: "responder issued by another CA", body: readGOST256OCSPFixture(t, "gost256-ocsp-foreign-issuer.der")},
	} {
		t.Run(test.name, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/ocsp-request" {
					t.Error("invalid GOST-256 OCSP HTTP request")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(body, wantRequest) {
					t.Error("GOST-256 request identifies the wrong certificate")
				}
				w.Header().Set("Content-Type", "application/ocsp-response")
				_, _ = w.Write(test.body)
			}))
			defer server.Close()
			client := ocspTestClient(t, server.URL)
			defer client.Close()
			native := ocspTestNative(t, client)
			validateNative := native.validateCertificateFunc
			nativeCalls := 0
			native.validateCertificateFunc = func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
				nativeCalls++
				return validateNative(req)
			}
			result, err := client.ValidateCertificate(t.Context(), ValidateCertificateRequest{
				Certificate: DER(leaf.Raw), Issuer: DER(issuer.Raw),
				Mode: CertificateValidationOCSP, ReturnOCSPResponse: true,
			})
			if test.valid {
				if err != nil || result == nil || result.Info != "chain ok" || !bytes.Equal(result.OCSPResponse, answer) {
					t.Fatalf("independently signed GOST-256 response: result=%+v, error=%v", result, err)
				}
			} else if result != nil || err == nil || !strings.Contains(err.Error(), "signed neither") {
				t.Fatalf("unauthenticated or unauthorized GOST-256 response: result=%+v, error=%v", result, err)
			}
			if hits.Load() != 1 || nativeCalls != 1 {
				t.Fatalf("GOST-256 validation calls: HTTP=%d, native=%d; want one chain validation and one OCSP request", hits.Load(), nativeCalls)
			}
		})
	}
}
