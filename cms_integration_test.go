package kalkan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

// These checks require the real SDK: mocks cannot prove whether native code
// interprets an input buffer as a filename. Existing files provide controls.
func TestVerifyCMSDistinguishesBytesFromFileSources(t *testing.T) {
	ctx := context.Background()
	client := openFixtureClient(t, loadFixtureAssets(t))
	fixture := documentCMSFixtures[0]
	payload := readDocumentCMSFixture(t, fixture, "document.txt")
	payloadPath := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, detached := range []bool{false, true} {
		kind := "attached.der"
		if detached {
			kind = "detached.der"
		}
		der := readDocumentCMSFixture(t, fixture, kind)
		for _, encoding := range []Encoding{EncodingAuto, EncodingRaw, EncodingDER, EncodingBase64, EncodingPEM} {
			encoded := der
			switch encoding {
			case EncodingBase64:
				encoded = []byte(base64.StdEncoding.EncodeToString(der))
			case EncodingPEM:
				encoded = pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: der})
			}
			for _, dataEncoding := range []Encoding{EncodingRaw, EncodingBase64} {
				if !detached && dataEncoding == EncodingBase64 {
					continue
				}
				t.Run(fmt.Sprintf("detached=%t/signature=%s/data=%s", detached, encodingName(encoding), encodingName(dataEncoding)), func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "signature.cms")
					if err := os.WriteFile(path, encoded, 0o600); err != nil {
						t.Fatal(err)
					}
					req := VerifyCMSRequest{Signature: Bytes(encoded).WithEncoding(encoding), Detached: detached, CertificateTimeCheck: SkipCertificateTimeCheck}
					dataSource := func(data []byte) Source {
						if dataEncoding == EncodingBase64 {
							return Base64([]byte(base64.StdEncoding.EncodeToString(data)))
						}
						return Bytes(data)
					}
					if detached {
						req.Data = dataSource(payload)
					}
					for _, file := range []bool{false, true} {
						t.Run(fmt.Sprintf("file=%t", file), func(t *testing.T) {
							req := req
							if file {
								req.Signature = File(path).WithEncoding(encoding)
							}
							verified, err := client.VerifyCMS(ctx, req)
							if err != nil {
								t.Fatalf("positive control: %v", err)
							}
							requireContains(t, "verification", verified.Info, "Verify - OK")
							if !detached && !file && !bytes.Equal(verified.Data, payload) {
								t.Fatal("attached payload differs")
							}
							if detached {
								bad := req
								bad.Data = dataSource([]byte(payloadPath))
								_, err := client.VerifyCMS(ctx, bad)
								requireNativeErrorCode(t, "payload path bytes", err, 0x2E09A09E)
							}
						})
					}
					// The identical existing signature path is rejected without File.
					req.Signature = Bytes([]byte(path)).WithEncoding(encoding)
					_, err := client.VerifyCMS(ctx, req)
					requireKalkanError(t, "signature path bytes", err)
				})
			}
		}
	}
}

func TestVerifyCMSFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)

	t.Run("attached timestamped CMS", func(t *testing.T) {
		cms := readFixtureExample(t, assets, "test_CMS_GOST")
		verification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
			Signature:            PEM(cms),
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("VerifyCMS(test_CMS_GOST) failed: %v", err)
		}
		requireContains(t, "test_CMS_GOST verification", verification.Info, "Verify - OK")
		requireContains(t, "test_CMS_GOST verification", verification.Info, "CAdES-T")
		if len(verification.Data) == 0 {
			t.Fatal("VerifyCMS(test_CMS_GOST) returned empty attached data")
		}

		if _, err := client.GetTimeFromSig(ctx, PEM(cms)); err == nil {
			t.Fatal("GetTimeFromSig(test_CMS_GOST) unexpectedly succeeded for expired CMS fixture fixture")
		} else {
			requireKalkanError(t, "GetTimeFromSig(test_CMS_GOST)", err)
		}
	})

	t.Run("detached CMS without data", func(t *testing.T) {
		cms := readFixtureExample(t, assets, "CMS_for_double_sign")
		if _, err := client.GetTimeFromSig(ctx, PEM(cms)); !isKalkanErrorCode(err, ckalkan.ErrorNoTSAToken) {
			t.Fatalf("GetTimeFromSig(CMS_for_double_sign) error = %v, want ErrorNoTSAToken", err)
		}
		if _, err := client.VerifyCMS(ctx, VerifyCMSRequest{
			Signature:            PEM(cms),
			CertificateTimeCheck: SkipCertificateTimeCheck,
		}); err == nil {
			t.Fatal("VerifyCMS(CMS_for_double_sign without detached data) unexpectedly succeeded")
		} else {
			requireKalkanError(t, "VerifyCMS(CMS_for_double_sign without detached data)", err)
		}
	})
}

func TestVerifyDocumentCMSFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)

	for _, fixture := range documentCMSFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			document := readDocumentCMSFixture(t, fixture, "document.txt")
			detachedSignature := readDocumentCMSFixture(t, fixture, "detached.der")
			attachedSignature := readDocumentCMSFixture(t, fixture, "attached.der")
			for _, input := range []struct {
				name        string
				signature   Source
				data        Source
				detached    bool
				wantPayload bool
			}{
				{
					name:      "detached DER",
					signature: DER(detachedSignature),
					data:      Bytes(document),
					detached:  true,
				},
				{
					name:      "detached Base64",
					signature: Base64([]byte(base64.StdEncoding.EncodeToString(detachedSignature))),
					data:      Bytes(document),
					detached:  true,
				},
				{
					name:        "attached DER",
					signature:   DER(attachedSignature),
					wantPayload: true,
				},
				{
					name:        "attached Base64",
					signature:   Base64([]byte(base64.StdEncoding.EncodeToString(attachedSignature))),
					wantPayload: true,
				},
			} {
				t.Run(input.name, func(t *testing.T) {
					// These fixtures exercise CMS encoding and attachment variants. Their
					// certificates are time-bounded test assets, so certificate-time policy
					// is covered separately by deterministic unit tests.
					verification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
						Signature:            input.signature,
						Data:                 input.data,
						Detached:             input.detached,
						CertificateTimeCheck: SkipCertificateTimeCheck,
					})
					if err != nil {
						t.Fatalf("VerifyCMS failed: %v", err)
					}
					requireContains(t, "verification", verification.Info, "Verify - OK")
					if input.wantPayload && !bytes.Equal(verification.Data, document) {
						t.Fatalf("VerifyCMS data = %q, want attached document", verification.Data)
					}
				})
			}
		})
	}
}
