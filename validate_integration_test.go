package kalkan

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"testing"
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
