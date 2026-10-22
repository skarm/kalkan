package kalkan

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
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
		// The SDK exposes this OpenSSL digest-verification error directly.
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

func TestXMLVerificationMatrix(t *testing.T) {
	client := openFixtureSigningClient(t)
	ctx := context.Background()
	for _, canon := range []struct {
		name  string
		value XMLCanonicalization
	}{
		{"inclusive", XMLCanonicalizationInclusive},
		{"inclusive-comments", XMLCanonicalizationInclusiveWithComments},
		{"inclusive-1.1", XMLCanonicalizationInclusive11},
		{"inclusive-1.1-comments", XMLCanonicalizationInclusive11WithComments},
		{"exclusive", XMLCanonicalizationExclusive},
		{"exclusive-comments", XMLCanonicalizationExclusiveWithComments},
	} {
		for _, wsse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wsse_%v", canon.name, wsse), func(t *testing.T) {
				payload := Bytes([]byte(`<document xmlns="urn:kalkan:matrix"><!--comment--><payload>original-value Кириллица</payload></document>`))
				var signed *SignedXML
				var err error
				request := VerifyXMLRequest{Canonicalization: canon.value, CertificateTimeCheck: SkipCertificateTimeCheck}
				if wsse {
					signed, err = client.SignWSSE(ctx, SignWSSERequest{
						XML: payload, BodyID: "MatrixBody", WrapSOAP: true,
						Canonicalization: canon.value, CertificateTimeCheck: SkipCertificateTimeCheck,
					})
					request.ExpectedBodyID = "MatrixBody"
				} else {
					signed, err = client.SignXML(ctx, SignXMLRequest{
						XML: payload, Canonicalization: canon.value, CertificateTimeCheck: SkipCertificateTimeCheck,
					})
				}
				if err != nil || signed == nil {
					t.Fatalf("sign: %v", err)
				}
				request.XML = Bytes(signed.XML)
				control, err := client.VerifyXML(ctx, request)
				if wsse && canon.value != XMLCanonicalizationExclusive {
					// The public SOAP policy deliberately rejects all other Body
					// transforms. Check native cryptography separately, retaining
					// this public rejection as an explicit assertion.
					if !errors.Is(err, ErrInvalidInput) || control != nil || !strings.Contains(err.Error(), "ds:Transform Algorithm is not allowed") {
						t.Fatalf("SOAP transform policy = %+v, %v", control, err)
					}
					flags, flagErr := xmlSignatureFlags(canon.value, SkipCertificateTimeCheck)
					if flagErr != nil {
						t.Fatal(flagErr)
					}
					verify := func(document []byte) (string, error) {
						return withLockedLibraryResult(client, ctx, "VerifyXML", func(native xmlSignatures) (string, error) {
							return native.VerifyXML("", flags, document)
						})
					}
					if info, err := verify(signed.XML); err != nil || !strings.Contains(info, "OK") {
						t.Fatalf("native SOAP positive control = %q, %v", info, err)
					}
					for _, document := range [][]byte{bytes.Replace(signed.XML, []byte("original-value"), []byte("tampered-value"), 1), mutateXMLSignatureValue(t, signed.XML)} {
						_, err := verify(document)
						requireNativeErrorCode(t, "native VerifyXML(changed SOAP)", err, ckalkan.ErrorSignInvalid)
					}
					return
				}
				if err != nil || control == nil || !strings.Contains(control.Info, "OK") {
					t.Fatalf("positive control = %+v, %v", control, err)
				}
				for _, mutation := range []struct {
					name string
					xml  []byte
				}{
					{"payload", bytes.Replace(signed.XML, []byte("original-value"), []byte("tampered-value"), 1)},
					{"signature", mutateXMLSignatureValue(t, signed.XML)},
				} {
					t.Run(mutation.name, func(t *testing.T) {
						if bytes.Equal(mutation.xml, signed.XML) {
							t.Fatal("mutation did not change signed XML")
						}
						request.XML = Bytes(mutation.xml)
						result, err := client.VerifyXML(ctx, request)
						requireNativeErrorCode(t, "VerifyXML(changed "+mutation.name+")", err, ckalkan.ErrorSignInvalid)
						if result != nil {
							t.Fatalf("rejected XML returned successful output: %+v", result)
						}
					})
				}
				request.XML = Bytes(signed.XML)
				if wsse {
					request.ExpectedBodyID = "DifferentBody"
					if result, err := client.VerifyXML(ctx, request); !errors.Is(err, ErrInvalidInput) || result != nil {
						t.Fatalf("wrong SOAP Body binding = %+v, %v", result, err)
					}
					request.ExpectedBodyID = "MatrixBody"
				}
				if _, err := client.VerifyXML(ctx, request); err != nil {
					t.Fatalf("valid XML after rejections: %v", err)
				}
			})
		}
	}
}

func mutateXMLSignatureValue(t *testing.T, document []byte) []byte {
	t.Helper()
	decoder := xml.NewDecoder(bytes.NewReader(document))
	for {
		token, err := decoder.Token()
		if err != nil {
			t.Fatalf("find XML SignatureValue: %v", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Space != xmlnsDSig || start.Name.Local != "SignatureValue" {
			continue
		}
		begin := decoder.InputOffset()
		token, err = decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		value, ok := token.(xml.CharData)
		if !ok || len(bytes.TrimSpace(value)) == 0 {
			t.Fatal("empty XML SignatureValue")
		}
		result := bytes.Clone(document)
		for i, b := range value {
			if bytes.IndexByte([]byte(xmlWhitespaceChars), b) >= 0 {
				continue
			}
			result[int(begin)+i] = 'A'
			if b == 'A' {
				result[int(begin)+i] = 'B'
			}
			return result
		}
		t.Fatal("XML SignatureValue has no base64 characters")
	}
}
