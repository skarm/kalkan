package javakalkan_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/kalkan"
)

func TestJavaHistoricalCertificateValidation(t *testing.T) {
	requireJavaValidationProvider(t)
	pki := newJavaValidationPKI(t, "http://unused.invalid")
	checkedAt := pki.now.Add(-12 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(23), Subject: pkix.Name{CommonName: "Expired historical signer"},
		NotBefore: pki.now.Add(-20 * time.Hour), NotAfter: pki.now.Add(-6 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	identity := javaValidationIssue(t, template, pki.intermediate)
	client := openJavaIntegrationClient(t, pki.trust(t)...)
	req := kalkan.ValidateCertificateRequest{Certificate: kalkan.DER(identity.cert.Raw), Mode: kalkan.CertificateValidationNone, CheckTime: checkedAt}
	if _, err := client.ValidateCertificate(t.Context(), req); err != nil {
		t.Fatalf("certificate valid at historical date: %v", err)
	}
	req.CheckTime = time.Time{}
	if _, err := client.ValidateCertificate(t.Context(), req); err == nil {
		t.Fatal("expired certificate passed current validation")
	}
	req.CertificateTimeCheck = kalkan.SkipCertificateTimeCheck
	if _, err := client.ValidateCertificate(t.Context(), req); err != nil {
		t.Fatalf("explicit current date skip: %v", err)
	}
	req.CheckTime = identity.cert.NotBefore.Add(-time.Hour)
	if _, err := client.ValidateCertificate(t.Context(), req); err == nil {
		t.Fatal("SkipCertificateTimeCheck bypassed the explicit CheckTime")
	}
	req.CheckTime = checkedAt
	if _, err := client.ValidateCertificate(t.Context(), req); err != nil {
		t.Fatalf("historical validation did not recover after rejected date: %v", err)
	}
	untrusted := openJavaIntegrationClient(t)
	if _, err := untrusted.ValidateCertificate(t.Context(), req); err == nil {
		t.Fatal("historical None/Skip accepted an untrusted chain")
	}

	for _, tc := range []struct {
		name      string
		revokedAt time.Time
		valid     bool
	}{
		{"unrevoked", time.Time{}, true},
		{"revoked before CheckTime", checkedAt.Add(-time.Minute), false},
		{"revoked at CheckTime", checkedAt, false},
		{"revoked after CheckTime", checkedAt.Add(time.Minute), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var serial *big.Int
			if !tc.revokedAt.IsZero() {
				serial = identity.cert.SerialNumber
			}
			directory := t.TempDir()
			for name, der := range map[string][]byte{
				"root.crl":         javaHistoricalCRL(t, pki.root, checkedAt, nil, time.Time{}),
				"intermediate.crl": javaHistoricalCRL(t, pki.intermediate, checkedAt, serial, tc.revokedAt),
			} {
				if err := os.WriteFile(filepath.Join(directory, name), der, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			crlRequest := req
			crlRequest.Mode, crlRequest.RevocationSource = kalkan.CertificateValidationCRL, directory
			_, err := client.ValidateCertificate(t.Context(), crlRequest)
			if tc.valid && err != nil {
				t.Fatalf("historical CRL validation: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("historically revoked certificate passed CRL validation")
			}
			// The same signed CRLs expired hours ago: applying current time must
			// reject them, even when certificate date checks are disabled.
			crlRequest.CheckTime = time.Time{}
			if _, err := client.ValidateCertificate(t.Context(), crlRequest); err == nil {
				t.Fatal("historical CRL was accepted as current evidence")
			}
		})
	}
	t.Run("current CRL is not historical evidence", func(t *testing.T) {
		bundle := append(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: pki.crl(t, pki.root, "good")}),
			pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: pki.crl(t, pki.intermediate, "good")})...)
		crlRequest := req
		crlRequest.Mode = kalkan.CertificateValidationCRL
		crlRequest.RevocationSource = javaIntegrationFile(t, "current-crls.pem", bundle)
		if _, err := client.ValidateCertificate(t.Context(), crlRequest); err == nil {
			t.Fatal("CRLs issued 12 hours after CheckTime were accepted for historical validation")
		}
	})
	// Per-request CRL configuration and historical dates must not leak into
	// the existing offline CMS client after either successful or failed checks.
	payload := []byte("current CMS after historical certificate validation")
	javaIntegrationVerify(t, client, kalkan.VerifyCMSRequest{Signature: kalkan.DER(pki.cms(t, payload, "none")), SignerID: 1}, payload)
}

func TestJavaCMSOCSPValidation(t *testing.T) {
	requireJavaValidationProvider(t)
	var pki *javaValidationPKI
	var fault atomic.Value
	fault.Store("good")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/ocsp" {
			t.Errorf("unexpected OCSP request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if fault.Load() == "unavailable" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return
		}
		currentFault, _ := fault.Load().(string)
		response, err := pki.ocsp(body, currentFault)
		if err != nil {
			t.Errorf("create OCSP response: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)
	pki = newJavaValidationPKI(t, server.URL)
	// Exercise the public default: no WithJavaRevocation option is supplied.
	options := append(pki.trust(t), kalkan.WithOCSPURL(server.URL+"/ocsp"))
	client := openJavaClientWithOptions(t, options...)
	payload := []byte("OCSP validation must authenticate status for the complete signer chain")
	request := kalkan.VerifyCMSRequest{Signature: kalkan.DER(pki.cms(t, payload, "none")), SignerID: 1}

	for _, tc := range []struct {
		fault string
		valid bool
	}{
		{"good", true},
		{"delegated good", true},
		{"delegated expired then valid", true},
		{"delegated future then valid", true},
		{"delegated not valid at producedAt then valid", true},
		{"delegated wrong usage then valid", true},
		{"delegated wrong usage only", false},
		{"delegated expired only", false},
		{"delegated future only", false},
		{"delegated not valid at producedAt only", false},
		// The selected policy accepts nonce-free responses within their validity
		// interval, while rejecting an explicitly mismatched nonce.
		{"missing nonce", true},
		{"revoked", false},
		{"revoked intermediate", false},
		{"unknown", false},
		{"stale", false},
		{"future thisUpdate", false},
		{"wrong certificate", false},
		{"wrong issuer", false},
		{"wrong nonce", false},
		{"forged signature", false},
		{"unauthorized responder", false},
		{"delegated wrong issuer", false},
		{"unavailable", false},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			fault.Store(tc.fault)
			before := requests.Load()
			if tc.valid {
				javaIntegrationVerify(t, client, request, payload)
				if requests.Load()-before < 2 {
					t.Fatal("OCSP did not check both signer and intermediate certificates")
				}
			} else {
				javaValidationReject(t, client, request)
				// Skipping certificate dates must not bypass revocation checks.
				skipped := request
				skipped.CertificateTimeCheck = kalkan.SkipCertificateTimeCheck
				javaValidationReject(t, client, skipped)
				fault.Store("good")
				javaIntegrationVerify(t, client, request, payload)
			}
		})
	}

	t.Run("standalone certificate and response", func(t *testing.T) {
		fault.Store("good")
		req := kalkan.ValidateCertificateRequest{
			Certificate: kalkan.DER(pki.leaf.cert.Raw), Mode: kalkan.CertificateValidationOCSP,
			RevocationSource: server.URL + "/ocsp", ReturnOCSPResponse: true,
		}
		result, err := client.ValidateCertificate(context.Background(), req)
		if err != nil || result == nil || len(result.OCSPResponse) == 0 {
			t.Fatalf("ValidateCertificate = %#v, %v", result, err)
		}
		fault.Store("revoked")
		if _, err := client.ValidateCertificate(context.Background(), req); err == nil {
			t.Fatal("standalone validation accepted a revoked signer certificate")
		}
		fault.Store("good")
		req.ReturnOCSPResponse = false
		result, err = client.ValidateCertificate(context.Background(), req)
		if err != nil || len(result.OCSPResponse) != 0 {
			t.Fatalf("unrequested OCSP response = %#v, %v", result, err)
		}
		req.CheckTime = time.Now().Add(-time.Hour)
		if _, err := client.ValidateCertificate(context.Background(), req); !errors.Is(err, kalkan.ErrJavaUnsupported) {
			t.Fatalf("historical validation must be explicitly unsupported: %v", err)
		}
		// A per-request offline mode must not leak into subsequent CMS checks.
		fault.Store("revoked")
		offline := kalkan.ValidateCertificateRequest{Certificate: kalkan.DER(pki.leaf.cert.Raw), Mode: kalkan.CertificateValidationNone}
		if _, err := client.ValidateCertificate(context.Background(), offline); err != nil {
			t.Fatalf("explicit offline standalone validation: %v", err)
		}
		javaValidationReject(t, client, request)
		fault.Store("good")
	})
}

func TestJavaCMSCRLValidation(t *testing.T) {
	requireJavaValidationProvider(t)
	var crls atomic.Value
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("CRL request method = %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		currentCRLs, _ := crls.Load().(map[string][]byte)
		data := currentCRLs[r.URL.Path]
		if data == nil {
			t.Errorf("unexpected CRL URL %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(data)
	}))
	t.Cleanup(server.Close)
	pki := newJavaValidationPKI(t, server.URL)
	good := map[string][]byte{
		"/root.crl": pki.crl(t, pki.root, "good"), "/intermediate.crl": pki.crl(t, pki.intermediate, "good"),
	}
	crls.Store(good)
	client := openJavaIntegrationClient(t, append(pki.trust(t), kalkan.WithJavaRevocation(kalkan.CertificateValidationCRL, ""))...)
	payload := []byte("CRL validation must authenticate current issuer revocation lists")
	request := kalkan.VerifyCMSRequest{Signature: kalkan.DER(pki.cms(t, payload, "none")), SignerID: 1}
	javaIntegrationVerify(t, client, request, payload)
	if requests.Load() < 2 {
		t.Fatal("CRL did not check both signer and intermediate certificates")
	}
	t.Run("certificate URL obeys endpoint policy", func(t *testing.T) {
		options := append(pki.trust(t), kalkan.WithJavaRevocation(kalkan.CertificateValidationCRL, ""),
			kalkan.WithEndpointPolicy(kalkan.EndpointPolicy{AllowedHosts: []string{"crl.example"}}))
		blocked := openJavaClientWithOptions(t, options...)
		before := requests.Load()
		javaValidationReject(t, blocked, request)
		if requests.Load() != before {
			t.Fatal("certificate distribution point bypassed the endpoint policy")
		}
	})
	for _, fault := range []string{
		"revoked", "revoked intermediate", "stale", "future thisUpdate", "wrong issuer", "forged signature", "delta CRL", "indirect CRL",
	} {
		t.Run(fault, func(t *testing.T) {
			bad := map[string][]byte{"/root.crl": good["/root.crl"], "/intermediate.crl": good["/intermediate.crl"]}
			if fault == "revoked intermediate" {
				bad["/root.crl"] = pki.crl(t, pki.root, fault)
			} else {
				bad["/intermediate.crl"] = pki.crl(t, pki.intermediate, fault)
			}
			crls.Store(bad)
			javaValidationReject(t, client, request)
			skipped := request
			skipped.CertificateTimeCheck = kalkan.SkipCertificateTimeCheck
			javaValidationReject(t, client, skipped)
			crls.Store(good)
			javaIntegrationVerify(t, client, request, payload)
		})
	}

	t.Run("local directory", func(t *testing.T) {
		directory := t.TempDir()
		for path, der := range good {
			if err := os.WriteFile(filepath.Join(directory, filepath.Base(path)), der, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		local := openJavaIntegrationClient(t, append(pki.trust(t), kalkan.WithJavaRevocation(kalkan.CertificateValidationCRL, directory))...)
		before := requests.Load()
		javaIntegrationVerify(t, local, request, payload)
		if requests.Load() != before {
			t.Fatal("local CRL configuration unexpectedly contacted the network")
		}
	})
	t.Run("local PEM bundle", func(t *testing.T) {
		bundle := make([]byte, 0, 2*(len(good["/root.crl"])+len(good["/intermediate.crl"])))
		for _, path := range []string{"/root.crl", "/intermediate.crl"} {
			bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: good[path]})...)
		}
		path := javaIntegrationFile(t, "crls.pem", bundle)
		local := openJavaIntegrationClient(t, append(pki.trust(t), kalkan.WithJavaRevocation(kalkan.CertificateValidationCRL, path))...)
		javaIntegrationVerify(t, local, request, payload)
		validation, err := local.ValidateCertificate(context.Background(), kalkan.ValidateCertificateRequest{
			Certificate: kalkan.DER(pki.leaf.cert.Raw), Mode: kalkan.CertificateValidationCRL, RevocationSource: path,
		})
		if err != nil || validation == nil || !strings.Contains(validation.Info, "crl OK") {
			t.Fatalf("standalone CRL validation = %#v, %v", validation, err)
		}
	})
}

func TestJavaCRLBundleSelection(t *testing.T) {
	requireJavaValidationProvider(t)
	pki := newJavaValidationPKI(t, "http://unused.invalid")
	client := openJavaIntegrationClient(t, pki.trust(t)...)
	updated, next := pki.now.Add(-time.Minute), pki.now.Add(time.Hour)
	root := javaValidationNumberedCRL(t, pki.root, 1, updated, next, nil)
	good := javaValidationNumberedCRL(t, pki.intermediate, 2, updated, next, nil)
	stale := javaValidationNumberedCRL(t, pki.intermediate, 1, pki.now.Add(-2*time.Hour), pki.now.Add(-time.Hour), nil)
	revoked := javaValidationNumberedCRL(t, pki.intermediate, 3, updated, next, pki.leaf.cert.SerialNumber)
	for _, tc := range []struct {
		name  string
		lists [][]byte
		valid bool
	}{
		{"current control", [][]byte{root, good}, true},
		{"stale then current", [][]byte{root, stale, good}, true},
		{"current then stale", [][]byte{root, good, stale}, true},
		{"newer revoked CRL in same second", [][]byte{root, good, revoked}, false},
		{"newer revoked CRL listed first", [][]byte{root, revoked, good}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bundle []byte
			for _, list := range tc.lists {
				bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: list})...)
			}
			path := javaIntegrationFile(t, "crls.pem", bundle)
			_, err := client.ValidateCertificate(t.Context(), kalkan.ValidateCertificateRequest{
				Certificate: kalkan.DER(pki.leaf.cert.Raw), Mode: kalkan.CertificateValidationCRL, RevocationSource: path,
			})
			if tc.valid && err != nil {
				t.Fatalf("bundle with a valid current CRL was rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("newer CRL contains revocation but the older good CRL was accepted")
			}
		})
	}
}

func TestJavaExplicitCRLSourceKeepsScopePolicy(t *testing.T) {
	requireJavaValidationProvider(t)
	pki := newJavaValidationPKI(t, "http://unused.invalid")
	client := openJavaIntegrationClient(t, pki.trust(t)...)
	template := *pki.leaf.cert
	for _, ext := range template.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
			continue
		}
		var points []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &points); err != nil {
			t.Fatal(err)
		}
		// Add a reason partition to the existing URI distribution point.
		points[0].FullBytes = nil
		points[0].Bytes = append(points[0].Bytes, 0x81, 0x02, 0x06, 0x40)
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: ext.Id, Value: javaValidationASN1(t, points)})
	}
	leaf := javaValidationIssue(t, &template, pki.intermediate)
	if _, err := client.ValidateCertificate(t.Context(), kalkan.ValidateCertificateRequest{Certificate: kalkan.DER(leaf.cert.Raw), Mode: kalkan.CertificateValidationNone}); err != nil {
		t.Fatal(err)
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: pki.crl(t, pki.root, "good")})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: pki.crl(t, pki.intermediate, "good")})...)
	_, err := client.ValidateCertificate(t.Context(), kalkan.ValidateCertificateRequest{Certificate: kalkan.DER(leaf.cert.Raw), Mode: kalkan.CertificateValidationCRL, RevocationSource: javaIntegrationFile(t, "full.crl", bundle)})
	if !errors.Is(err, kalkan.ErrJavaUnsupported) {
		t.Fatalf("explicit source changed unsupported CRL-scope policy: %v", err)
	}
}
