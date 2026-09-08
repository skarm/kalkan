package javakalkan_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/internal/testfixture"
)

func TestJavaCMSTimestampSigningAndExtraction(t *testing.T) {
	requireJavaValidationProvider(t)
	var pki *javaValidationPKI
	var fault atomic.Value
	fault.Store("good")
	var tsaRequests, ocspRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/tsa":
			if r.Header.Get("Content-Type") != "application/timestamp-query" {
				t.Errorf("TSA content type = %q", r.Header.Get("Content-Type"))
			}
			tsaRequests.Add(1)
			currentFault, _ := fault.Load().(string)
			if currentFault == "unavailable" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/timestamp-reply")
			_, _ = w.Write(javaValidationTSAResponse(t, pki, body, currentFault))
		case "/ocsp":
			ocspRequests.Add(1)
			currentFault := "good"
			if fault.Load() == "revoked TSA" {
				currentFault = "revoked TSA"
			}
			response, err := pki.ocsp(body, currentFault)
			if err != nil {
				t.Error(err)
				return
			}
			w.Header().Set("Content-Type", "application/ocsp-response")
			_, _ = w.Write(response)
		default:
			t.Errorf("unexpected endpoint: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	pki = newJavaValidationPKI(t, server.URL)
	options := append(pki.trust(t), kalkan.WithTSAURL(server.URL+"/tsa"), kalkan.WithOCSPURL(server.URL+"/ocsp"))
	client := openJavaClientWithOptions(t, options...)
	store := javaValidationKeyStore(t, pki.leaf)
	if err := client.LoadKeyStore(t.Context(), kalkan.KeyStore{Type: kalkan.PKCS12, Path: store, Password: "test-password"}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("Timestamped CMS with a current, generated RSA signer\x00\xff")
	for _, detached := range []bool{false, true} {
		t.Run(fmt.Sprintf("detached=%t", detached), func(t *testing.T) {
			signed, err := client.SignCMS(t.Context(), kalkan.SignCMSRequest{
				Data: kalkan.Bytes(payload), Detached: detached, Timestamp: true, IncludeCertificate: true,
			})
			if err != nil {
				t.Fatalf("SignCMS: %v", err)
			}
			req := kalkan.VerifyCMSRequest{Signature: kalkan.DER(signed.Data), Detached: detached, SignerID: 1}
			if detached {
				req.Data = kalkan.Bytes(payload)
			}
			javaIntegrationVerify(t, client, req, payload)
			got, err := client.GetTimeFromSig(t.Context(), kalkan.DER(signed.Data))
			if err != nil || !got.Equal(pki.now) {
				t.Fatalf("GetTimeFromSig = %v, %v; want %v", got, err, pki.now)
			}
			var envelope testfixture.CMSEnvelope
			if _, err := asn1.Unmarshal(signed.Data, &envelope); err != nil {
				t.Fatal(err)
			}
			envelope.Content.SignerInfos[0].Signature[0] ^= 1
			if _, err := client.GetTimeFromSig(t.Context(), kalkan.DER(javaValidationASN1(t, envelope))); err == nil {
				t.Fatal("timestamp extraction accepted an imprint bound to a different CMS signature")
			}
		})
	}
	t.Run("precomputed hash", func(t *testing.T) {
		digest := sha256.Sum256(payload)
		signed, err := client.SignHash(t.Context(), kalkan.SignHashRequest{Digest: digest[:], Timestamp: true, IncludeCertificate: true})
		if err != nil {
			t.Fatalf("SignHash: %v", err)
		}
		javaIntegrationVerify(t, client, kalkan.VerifyCMSRequest{Signature: kalkan.DER(signed.Data), Data: kalkan.Bytes(payload), Detached: true, SignerID: 1}, payload)
	})
	for _, currentFault := range []string{"wrong nonce", "missing nonce", "wrong imprint", "forged token", "untrusted TSA", "wrong TSA usage", "old token", "future token", "rejected request", "unavailable", "revoked TSA"} {
		t.Run(currentFault, func(t *testing.T) {
			fault.Store(currentFault)
			if _, err := client.SignCMS(t.Context(), kalkan.SignCMSRequest{Data: kalkan.Bytes(payload), Timestamp: true, IncludeCertificate: true}); err == nil {
				t.Fatal("SignCMS accepted invalid TSA response")
			}
			fault.Store("good")
			if _, err := client.SignCMS(t.Context(), kalkan.SignCMSRequest{Data: kalkan.Bytes(payload), Timestamp: true, IncludeCertificate: true}); err != nil {
				t.Fatalf("worker did not recover after rejected timestamp: %v", err)
			}
		})
	}
	t.Run("extraction authenticates TSA and current revocation", func(t *testing.T) {
		for _, invalid := range []string{"wrong imprint", "forged token signature", "untrusted TSA", "wrong TSA usage", "wrong ESS certificate", "future token", "TSA expired at genTime"} {
			if _, err := client.GetTimeFromSig(t.Context(), kalkan.DER(pki.cms(t, payload, invalid))); err == nil {
				t.Fatalf("timestamp extraction accepted %s", invalid)
			}
		}
		valid := kalkan.DER(pki.cms(t, payload, "valid"))
		fault.Store("revoked TSA")
		if _, err := client.GetTimeFromSig(t.Context(), valid); err == nil {
			t.Fatal("timestamp extraction accepted a revoked TSA")
		}
		fault.Store("good")
		got, err := client.GetTimeFromSig(t.Context(), valid)
		if err != nil || !got.Equal(pki.now.Add(-time.Minute)) {
			t.Fatalf("timestamp extraction after failure = %v, %v", got, err)
		}
	})
	if tsaRequests.Load() < 3 || ocspRequests.Load() < 2 {
		t.Fatalf("missing timestamp/OCSP requests: %d/%d", tsaRequests.Load(), ocspRequests.Load())
	}
	t.Run("missing token", func(t *testing.T) {
		signed, err := client.SignCMS(t.Context(), kalkan.SignCMSRequest{Data: kalkan.Bytes(payload), IncludeCertificate: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.GetTimeFromSig(t.Context(), kalkan.DER(signed.Data)); err == nil {
			t.Fatal("CMS without a token returned a trusted timestamp")
		}
	})
}

func TestJavaCMSTimestampValidation(t *testing.T) {
	requireJavaValidationProvider(t)
	var pki *javaValidationPKI
	var fault atomic.Value
	fault.Store("good")
	var seen sync.Map
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return
		}
		var req javaValidationOCSPRequest
		if _, err := asn1.Unmarshal(body, &req); err != nil || len(req.TBS.Requests) != 1 {
			t.Errorf("invalid TSA revocation request: %v", err)
			return
		}
		seen.Store(req.TBS.Requests[0].CertID.SerialNumber.String(), true)
		currentFault, _ := fault.Load().(string)
		response, err := pki.ocsp(body, currentFault)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)
	pki = newJavaValidationPKI(t, server.URL)
	client := openJavaIntegrationClient(t, append(pki.trust(t), kalkan.WithJavaRevocation(kalkan.CertificateValidationOCSP, server.URL+"/ocsp"))...)
	payload := []byte("RFC3161 token must cover this CMS signature")
	signature := pki.cms(t, payload, "valid")
	valid := kalkan.VerifyCMSRequest{Signature: kalkan.DER(signature), SignerID: 1}
	javaIntegrationVerify(t, client, valid, payload)
	if _, checked := seen.Load(pki.tsa.cert.SerialNumber.String()); !checked {
		t.Fatal("timestamp validation omitted TSA certificate revocation")
	}
	for _, fault := range []string{
		"wrong imprint", "forged token signature", "untrusted TSA", "wrong TSA usage", "wrong ESS certificate", "future token", "TSA expired at genTime",
	} {
		t.Run(fault, func(t *testing.T) {
			bad := kalkan.VerifyCMSRequest{Signature: kalkan.DER(pki.cms(t, payload, fault)), SignerID: 1}
			javaValidationReject(t, client, bad)
			bad.CertificateTimeCheck = kalkan.SkipCertificateTimeCheck
			javaValidationReject(t, client, bad)
			javaIntegrationVerify(t, client, valid, payload)
		})
	}
	t.Run("revoked TSA", func(t *testing.T) {
		fault.Store("revoked TSA")
		javaValidationReject(t, client, valid)
		fault.Store("good")
		javaIntegrationVerify(t, client, valid, payload)
	})
	t.Run("primary document remains authenticated", func(t *testing.T) {
		tampered := bytes.Replace(signature, payload, []byte(strings.Repeat("x", len(payload))), 1)
		bad := valid
		bad.Signature = kalkan.DER(tampered)
		javaValidationReject(t, client, bad)
		javaIntegrationVerify(t, client, valid, payload)
	})
}

func TestJavaTimestampSignedAttributeTypes(t *testing.T) {
	requireJavaValidationProvider(t)
	pki := newJavaValidationPKI(t, "http://unused.invalid")
	client := openJavaIntegrationClient(t, pki.trust(t)...)
	original := pki.cms(t, []byte("timestamp content"), "good")
	if _, err := client.GetTimeFromSig(t.Context(), kalkan.DER(original)); err != nil {
		t.Fatal(err)
	}
	var envelope, token testfixture.CMSEnvelope
	if _, err := asn1.Unmarshal(original, &envelope); err != nil {
		t.Fatal(err)
	}
	timestamp := &envelope.Content.SignerInfos[0].UnsignedAttributes[0].Values[0]
	if _, err := asn1.Unmarshal(timestamp.FullBytes, &token); err != nil {
		t.Fatal(err)
	}
	for i := range token.Content.SignerInfos[0].SignedAttributes {
		attribute := &token.Content.SignerInfos[0].SignedAttributes[i]
		if attribute.Type.Equal(javaOIDMessageHash) {
			attribute.Values = []asn1.RawValue{{FullBytes: javaValidationASN1(t, "invalid digest representation")}}
		}
	}
	javaValidationResign(t, pki.tsa, &token.Content.SignerInfos[0], nil)
	timestamp.FullBytes = javaValidationASN1(t, token)
	malformed := kalkan.DER(javaValidationASN1(t, envelope))
	if _, err := client.GetTimeFromSig(t.Context(), malformed); err == nil {
		t.Fatal("timestamp extraction accepted malformed signed digest")
	}
	if _, err := client.VerifyCMS(t.Context(), kalkan.VerifyCMSRequest{Signature: malformed}); err == nil {
		t.Fatal("CMS verification accepted malformed timestamp signed digest")
	}
}
