package kalkan

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientFixtureCertificateValidationEncodings(t *testing.T) {
	ctx := context.Background()
	client := openFixtureSigningClient(t)
	certificate, err := client.X509ExportCertificateFromStore(ctx)
	if err != nil {
		t.Fatalf("export signer certificate: %v", err)
	}
	der := certificate.Raw
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, tc := range []struct {
		name   string
		source Source
	}{
		{"DER", DER(der)},
		{"PEM", PEM(encoded)},
		{"base64", Base64([]byte(base64.StdEncoding.EncodeToString(der)))},
		{"raw PEM", Bytes(encoded)},
		{"auto PEM", Bytes(encoded).WithEncoding(EncodingAuto)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{Certificate: tc.source, Mode: CertificateValidationNone, CertificateTimeCheck: SkipCertificateTimeCheck})
			if err != nil || result == nil {
				t.Fatalf("ValidateCertificate = %#v, %v, want successful positive control", result, err)
			}
			requireContains(t, "certificate validation", result.Info, "- OK")
		})
	}
}

func TestClientFixtureKeyStoreRestoresConfiguredTrust(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	// openFixtureClient loads both chain certificates through WithTrustedCertificate.
	client := openFixtureClient(t, assets)
	store := KeyStore{Type: PKCS12, Path: keyStorePath(t, assets), Password: fixturePassword}
	for iteration := range 2 {
		if err := client.LoadKeyStore(ctx, store); err != nil {
			t.Fatalf("LoadKeyStore iteration %d: %v", iteration, err)
		}
		certificate, err := client.X509ExportCertificateFromStore(ctx)
		if err != nil {
			t.Fatalf("export signer certificate iteration %d: %v", iteration, err)
		}
		validation, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
			Certificate: DER(certificate.Raw), Mode: CertificateValidationNone,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil || validation == nil {
			t.Fatalf("ValidateCertificate iteration %d = %#v, %v", iteration, validation, err)
		}
		requireContains(t, "certificate validation after key-store load", validation.Info, "- OK")
		signed, err := client.SignXML(ctx, SignXMLRequest{
			XML:              Bytes([]byte(`<document><payload>configured trust</payload></document>`)),
			Canonicalization: XMLCanonicalizationInclusive, CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("SignXML iteration %d: %v", iteration, err)
		}
		verification, err := client.VerifyXML(ctx, VerifyXMLRequest{
			XML: Bytes(signed.XML), Canonicalization: XMLCanonicalizationInclusive,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil || verification == nil {
			t.Fatalf("VerifyXML iteration %d = %#v, %v", iteration, verification, err)
		}
		requireContains(t, "XML verification after key-store load", verification.Info, "OK")
	}
}

func TestClientFixtureCertificateValidationOmitsUnrequestedOCSPResponse(t *testing.T) {
	ctx := context.Background()
	client := openFixtureSigningClient(t)
	certificate, err := client.X509ExportCertificateFromStore(ctx)
	if err != nil {
		t.Fatalf("export signer certificate: %v", err)
	}
	result, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
		Certificate:          DER(certificate.Raw),
		Mode:                 CertificateValidationNone,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil || result == nil {
		t.Fatalf("ValidateCertificate = %#v, %v, want successful positive control", result, err)
	}
	requireContains(t, "certificate validation", result.Info, "- OK")
	if result.OCSPResponse != nil {
		t.Fatalf("unrequested OCSP response contains %d bytes, want nil", len(result.OCSPResponse))
	}
}

func TestLiveOCSPSignatureVerification(t *testing.T) {
	if os.Getenv("KALKANCRYPT_LIVE_TESTS") != "1" {
		t.Skip("set KALKANCRYPT_LIVE_TESTS=1 to contact the actual NCA test OCSP responder")
	}
	client := openFixtureSigningClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	leaf, err := client.X509ExportCertificateFromStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assets := loadFixtureAssets(t)
	issuerBytes, err := os.ReadFile(certificatePath(t, assets, "nca_gost2022_test"))
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(issuerBytes); block != nil {
		issuerBytes = block.Bytes
	}
	issuer, err := parseOCSPDERCertificate(issuerBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkOCSPIssuer(leaf, issuer); err != nil {
		t.Fatal(err)
	}
	id, err := kalkanOCSPCertID(leaf.SerialNumber, issuer)
	if err != nil {
		t.Fatal(err)
	}
	request, err := kalkanOCSPRequest(id)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := client.fetchOCSP(ctx, testOCSPURL, request)
	if err != nil {
		t.Fatal(err)
	}
	if dir := os.Getenv("KALKANCRYPT_LIVE_RESULTS"); dir != "" {
		for name, data := range map[string][]byte{"live-ocsp-request.der": request, "live-ocsp-response.der": answer} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	revokedAt, revoked, statusErr := kalkanOCSPStatus(answer, id, issuer, time.Now())
	// An authenticated unknown status is possible for expired fixture identities;
	// it proves the response signature, but cannot establish certificate validity.
	if statusErr != nil && statusErr.Error() != "the responder does not know the certificate" {
		t.Fatalf("live OCSP signature/status verification: %v", statusErr)
	}
	t.Logf("authenticated live OCSP response: bytes=%d revoked=%v revokedAt=%v statusError=%v", len(answer), revoked, revokedAt, statusErr)
	var response ocspResponse
	if rest, err := asn1.Unmarshal(answer, &response); err != nil || len(rest) != 0 {
		t.Fatalf("OCSP envelope: %v", err)
	}
	var basic ocspBasicResponse
	if rest, err := asn1.Unmarshal(response.Bytes.Response, &basic); err != nil || len(rest) != 0 {
		t.Fatalf("OCSP basic response: %v", err)
	}
	if len(basic.Signature.Bytes) == 0 || bytes.Count(answer, basic.Signature.Bytes) != 1 {
		t.Fatal("need one unambiguous OCSP signature value")
	}
	changed := bytes.Clone(answer)
	changed[bytes.Index(answer, basic.Signature.Bytes)+len(basic.Signature.Bytes)/2] ^= 1
	if _, _, err := kalkanOCSPStatus(changed, id, issuer, time.Now()); err == nil || err.Error() == "the responder does not know the certificate" {
		t.Fatalf("changed OCSP signature was not cryptographically rejected: %v", err)
	} else {
		t.Logf("changed OCSP signature rejected: %v", err)
	}
}
