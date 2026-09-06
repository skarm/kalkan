package kalkan

import (
	"bytes"
	"context"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestClientFixtureRejectsTamperedCryptographicInputs(t *testing.T) {
	ctx := context.Background()
	client := openFixtureSigningClient(t)

	t.Run("detached CMS payload", func(t *testing.T) {
		original := []byte("signed detached payload")
		signed, err := client.SignCMS(ctx, SignCMSRequest{
			Data:                 Bytes(original),
			Detached:             true,
			IncludeCertificate:   true,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("SignCMS failed: %v", err)
		}

		request := VerifyCMSRequest{
			Signature:            DER(signed.Data),
			Data:                 Bytes(original),
			Detached:             true,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		}
		verification, err := client.VerifyCMS(ctx, request)
		if err != nil || verification == nil {
			t.Fatalf("VerifyCMS(original) = %#v, %v, want a successful positive control", verification, err)
		}
		requireContains(t, "original detached CMS verification", verification.Info, "Verify - OK")

		request.Data = Bytes([]byte("tampered detached payload"))
		_, err = client.VerifyCMS(ctx, request)
		// SDK 2.0.13 exposes this OpenSSL digest-verification error directly.
		const cmsDigestVerificationFailure = ckalkan.ErrorCode(0x2E09A09E)
		requireNativeErrorCode(t, "VerifyCMS(tampered)", err, cmsDigestVerificationFailure)
	})

	t.Run("signed XML payload", func(t *testing.T) {
		signed, err := client.SignXML(ctx, SignXMLRequest{
			XML:                  Bytes([]byte(`<document><payload>original-value</payload></document>`)),
			Canonicalization:     XMLCanonicalizationInclusive,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("SignXML failed: %v", err)
		}

		request := VerifyXMLRequest{
			XML:                  Bytes(signed.XML),
			Canonicalization:     XMLCanonicalizationInclusive,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		}
		verification, err := client.VerifyXML(ctx, request)
		if err != nil || verification == nil {
			t.Fatalf("VerifyXML(original) = %#v, %v, want a successful positive control", verification, err)
		}
		requireContains(t, "original XML verification", verification.Info, "OK")

		tampered := bytes.Replace(signed.XML, []byte("original-value"), []byte("tampered-value"), 1)
		if bytes.Equal(tampered, signed.XML) {
			t.Fatal("signed XML did not contain the payload selected for tampering")
		}

		request.XML = Bytes(tampered)
		_, err = client.VerifyXML(ctx, request)
		requireNativeErrorCode(t, "VerifyXML(tampered)", err, ckalkan.ErrorSignInvalid)
	})

	t.Run("malformed certificate", func(t *testing.T) {
		certificate, err := client.X509ExportCertificateFromStore(ctx)
		if err != nil {
			t.Fatalf("export signer certificate: %v", err)
		}
		request := ValidateCertificateRequest{
			Certificate:          DER(certificate.Raw),
			Mode:                 CertificateValidationNone,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		}
		validation, err := client.ValidateCertificate(ctx, request)
		if err != nil || validation == nil {
			t.Fatalf("ValidateCertificate(original) = %#v, %v, want a successful positive control", validation, err)
		}

		request.Certificate = DER([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
		_, err = client.ValidateCertificate(ctx, request)
		requireNativeErrorCode(t, "ValidateCertificate(malformed DER)", err, ckalkan.ErrorCertParse)
	})
}
