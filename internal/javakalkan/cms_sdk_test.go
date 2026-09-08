package javakalkan_test

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/internal/testfixture"
)

func TestJavaCMSAppendSigner(t *testing.T) {
	requireJavaValidationProvider(t)
	pki := newJavaValidationPKI(t, "http://unused.invalid")
	client := openJavaIntegrationClient(t, pki.trust(t)...)
	secondTemplate := *pki.leaf.cert
	secondTemplate.SerialNumber = big.NewInt(10)
	secondTemplate.Subject.CommonName = "Second CMS signer"
	second := javaValidationIssue(t, &secondTemplate, pki.intermediate)
	store := javaValidationKeyStore(t, second)
	if err := client.LoadKeyStore(t.Context(), kalkan.KeyStore{Type: kalkan.PKCS12, Path: store, Password: "test-password"}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("Existing CMS content must be preserved while adding a signer")
	for _, detached := range []bool{false, true} {
		t.Run(fmt.Sprintf("detached=%t", detached), func(t *testing.T) {
			original := pki.cms(t, payload, "none")
			var before testfixture.CMSEnvelope
			if _, err := asn1.Unmarshal(original, &before); err != nil {
				t.Fatal(err)
			}
			if detached {
				before.Content.ContentInfo = asn1.RawValue{FullBytes: javaValidationASN1(t, struct{ Type asn1.ObjectIdentifier }{javaOIDData})}
				original = javaValidationASN1(t, before)
			}
			appendCMS := func(data kalkan.Source, existing []byte) ([]byte, error) {
				cms, err := client.SignCMS(t.Context(), kalkan.SignCMSRequest{
					Data: data, ExistingSignature: kalkan.DER(existing), Detached: detached, IncludeCertificate: true,
				})
				if err != nil {
					return nil, err
				}
				return cms.Data, nil
			}
			appended, err := appendCMS(kalkan.Bytes(payload), original)
			if err != nil {
				t.Fatalf("append: %v", err)
			}
			verifyAppend := func(t *testing.T, appended []byte) {
				t.Helper()
				var after testfixture.CMSEnvelope
				if _, err := asn1.Unmarshal(appended, &after); err != nil {
					t.Fatal(err)
				}
				if len(after.Content.SignerInfos) != 2 {
					t.Fatalf("appended signer count = %d", len(after.Content.SignerInfos))
				}
				retained := false
				for _, signer := range after.Content.SignerInfos {
					if bytes.Equal(javaValidationASN1(t, signer), javaValidationASN1(t, before.Content.SignerInfos[0])) {
						retained = true
					}
				}
				if !retained || !bytes.Equal(before.Content.ContentInfo.FullBytes, after.Content.ContentInfo.FullBytes) ||
					!bytes.Contains(after.Content.Certificates.Bytes, pki.leaf.cert.Raw) || !bytes.Contains(after.Content.Certificates.Bytes, second.cert.Raw) {
					t.Fatal("append did not preserve original content, signer or certificate")
				}
				for _, signerID := range []int{1, 2} {
					req := kalkan.VerifyCMSRequest{Signature: kalkan.DER(appended), Detached: detached, SignerID: signerID}
					if detached {
						req.Data = kalkan.Bytes(payload)
					}
					javaIntegrationVerify(t, client, req, payload)
				}
			}
			verifyAppend(t, appended)
			for _, encoding := range []struct {
				name   string
				format kalkan.Encoding
				data   []byte
			}{
				{"base64", kalkan.EncodingBase64, []byte(base64.StdEncoding.EncodeToString(payload))},
				{"PEM", kalkan.EncodingPEM, pem.EncodeToMemory(&pem.Block{Type: "DATA", Bytes: payload})},
			} {
				for _, fileInput := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/file=%t", encoding.name, fileInput), func(t *testing.T) {
						data := kalkan.Bytes(encoding.data).WithEncoding(encoding.format)
						if fileInput {
							data = kalkan.File(javaIntegrationFile(t, "encoded-payload", encoding.data)).WithEncoding(encoding.format)
						}
						appended, err := appendCMS(data, original)
						if err != nil {
							t.Fatalf("append encoded payload: %v", err)
						}
						verifyAppend(t, appended)
					})
				}
			}
			third, err := appendCMS(kalkan.Bytes(payload), appended)
			if err != nil {
				t.Fatalf("append same signer again: %v", err)
			}
			var three testfixture.CMSEnvelope
			if _, err := asn1.Unmarshal(third, &three); err != nil || len(three.Content.SignerInfos) != 3 {
				t.Fatalf("append must add a signer even when its attributes and signature repeat: %v, count %d", err, len(three.Content.SignerInfos))
			}
			if _, err := appendCMS(kalkan.Bytes([]byte("different payload")), original); err == nil {
				t.Fatal("append signed data inconsistent with existing CMS")
			}
			before.Content.SignerInfos[0].Signature[0] ^= 1
			if _, err := appendCMS(kalkan.Bytes(payload), javaValidationASN1(t, before)); err == nil {
				t.Fatal("append accepted an invalid existing CMS signature")
			}
		})
	}
}

func TestJavaCMS(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := openJavaIntegrationClient(t, javaIntegrationTrust(t, assets)...)
	loadJavaIntegrationKeyStore(t, client, assets)
	ctx := context.Background()
	payload := []byte("Java CMS integration: подписанный документ\x00\xff\n")
	payloadFile := javaIntegrationFile(t, "document.bin", payload)

	for _, detached := range []bool{false, true} {
		for _, format := range []struct {
			name     string
			output   kalkan.CMSOutputFormat
			encoding kalkan.Encoding
		}{
			{name: "DER", output: kalkan.CMSOutputDER, encoding: kalkan.EncodingDER},
			{name: "base64", output: kalkan.CMSOutputBase64, encoding: kalkan.EncodingBase64},
			{name: "PEM", output: kalkan.CMSOutputPEM, encoding: kalkan.EncodingPEM},
		} {
			for _, fileInput := range []bool{false, true} {
				t.Run(fmt.Sprintf("detached=%t/%s/file=%t", detached, format.name, fileInput), func(t *testing.T) {
					data := kalkan.Bytes(payload)
					if fileInput {
						data = kalkan.File(payloadFile)
					}
					signature, err := client.SignCMS(ctx, kalkan.SignCMSRequest{
						Data: data, Detached: detached, IncludeCertificate: true,
						OutputFormat: format.output, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
					})
					if err != nil {
						t.Fatalf("SignCMS: %v", err)
					}
					der := javaIntegrationCMSDER(t, signature.Data, format.output)
					content, certificates, err := testfixture.CMSContentAndCertificates(der)
					if err != nil {
						t.Fatalf("decode signed CMS: %v", err)
					}
					if len(certificates) == 0 {
						t.Fatal("CMS does not include requested signer certificate")
					}
					if detached && content != nil {
						t.Fatal("detached CMS contains encapsulated payload")
					}
					if !detached && !bytes.Equal(content, payload) {
						t.Fatal("attached CMS payload differs from input")
					}
					request := kalkan.VerifyCMSRequest{
						Signature: kalkan.Bytes(signature.Data).WithEncoding(format.encoding),
						Detached:  detached, SignerID: 1, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
					}
					if detached {
						// Check independent encodings for CMS and detached data.
						request.Data = kalkan.Base64([]byte(base64.StdEncoding.EncodeToString(payload)))
					}
					if fileInput {
						request.Signature = kalkan.File(javaIntegrationFile(t, "signature.cms", signature.Data)).WithEncoding(format.encoding)
					}
					wantPayload := payload
					if fileInput {
						wantPayload = nil
					}
					javaIntegrationVerify(t, client, request, wantPayload)

					bad := request
					if detached {
						modified := bytes.Clone(payload)
						modified[0] ^= 1
						bad.Data = kalkan.Bytes(modified)
					} else {
						// Change only the encapsulated document, preserving CMS ASN.1
						// and its signature, so this exercises cryptographic verification.
						modified := bytes.Clone(payload)
						modified[0] ^= 1
						if bytes.Count(der, payload) != 1 {
							t.Fatal("cannot locate unique attached payload in DER")
						}
						bad.Signature = kalkan.DER(bytes.Replace(der, payload, modified, 1))
					}
					if result, err := client.VerifyCMS(ctx, bad); err == nil {
						t.Fatalf("modified document verified: %#v", result)
					}
					// A crashed worker must not masquerade as a verification failure.
					javaIntegrationVerify(t, client, request, wantPayload)
				})
			}
		}
	}

	t.Run("explicit empty payload", func(t *testing.T) {
		for _, detached := range []bool{false, true} {
			t.Run(fmt.Sprintf("detached=%t", detached), func(t *testing.T) {
				signature, err := client.SignCMS(ctx, kalkan.SignCMSRequest{
					Data: kalkan.Bytes(nil), Detached: detached, IncludeCertificate: true,
					CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
				})
				if err != nil {
					t.Fatalf("SignCMS(empty): %v", err)
				}
				request := kalkan.VerifyCMSRequest{Signature: kalkan.DER(signature.Data), Detached: detached, SignerID: 1, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}
				if detached {
					request.Data = kalkan.Bytes(nil)
				}
				javaIntegrationVerify(t, client, request, nil)
			})
		}
	})

	t.Run("signer certificate", func(t *testing.T) {
		certificate, err := client.X509ExportCertificateFromStore(ctx)
		if err != nil || certificate == nil {
			t.Fatalf("X509ExportCertificateFromStore = %#v, %v", certificate, err)
		}
		signature, err := client.SignCMS(ctx, kalkan.SignCMSRequest{
			Data: kalkan.Bytes(payload), IncludeCertificate: true, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("SignCMS: %v", err)
		}
		for _, source := range []kalkan.Source{
			kalkan.DER(signature.Data), kalkan.File(javaIntegrationFile(t, "signed.der", signature.Data)),
		} {
			certificates, err := client.GetCertFromCMS(ctx, source)
			if err != nil {
				t.Fatalf("GetCertFromCMS: %v", err)
			}
			if len(certificates) != 1 || !bytes.Equal(certificates[0].Raw, certificate.Raw) {
				t.Fatal("CMS signer certificate differs from loaded PKCS#12 certificate")
			}
		}
		request := kalkan.VerifyCMSRequest{Signature: kalkan.DER(signature.Data), CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}
		verified, err := client.VerifyCMS(ctx, request)
		if err != nil || verified == nil {
			t.Fatalf("VerifyCMS(default SignerID) = %#v, %v", verified, err)
		}
		if !bytes.Equal(verified.Data, payload) || len(verified.SignerCert) != 0 {
			t.Fatal("default SignerID must verify the payload without requesting a signer certificate")
		}
		request.SignerID = 2
		if _, err := client.VerifyCMS(ctx, request); err == nil {
			t.Fatal("VerifyCMS accepted a missing signer certificate index")
		}
	})

	t.Run("precomputed digest", func(t *testing.T) {
		digest, err := client.Hash(ctx, kalkan.HashRequest{Algorithm: kalkan.GOST2015_512, Data: kalkan.Bytes(payload)})
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		signature, err := client.SignHash(ctx, kalkan.SignHashRequest{
			Digest: digest.Data, DigestAlgorithm: digest.Algorithm,
			IncludeCertificate: true, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("SignHash: %v", err)
		}
		testfixture.AssertSignHashCMSStructure(t, signature.Data, digest.Data)
		request := kalkan.VerifyCMSRequest{
			Signature: kalkan.DER(signature.Data), Data: kalkan.Bytes(payload), Detached: true, SignerID: 1,
			CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
		}
		javaIntegrationVerify(t, client, request, payload)
		request.Data = kalkan.Bytes([]byte("another document"))
		if _, err := client.VerifyCMS(ctx, request); err == nil {
			t.Fatal("SignHash CMS verified against a different document")
		}
		request.Data = kalkan.Bytes(payload)
		javaIntegrationVerify(t, client, request, payload)
	})
}

func TestJavaVerifiesNativeCMSFixtures(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := openJavaIntegrationClient(t, javaIntegrationTrust(t, assets)...)
	var tsaClient *kalkan.Client
	if directory := os.Getenv("KALKANCRYPT_JAVA_TSA_CERTIFICATES"); directory != "" {
		options := append(javaIntegrationTrust(t, assets),
			kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{Path: filepath.Join(directory, "root_gost_2022.cer"), Type: kalkan.CertificateCA}),
			kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{Path: filepath.Join(directory, "nca_gost_2022.cer"), Type: kalkan.CertificateIntermediate}),
		)
		tsaClient = openJavaIntegrationClient(t, options...)
	}
	for _, fixture := range documentCMSFixtures {
		for _, detached := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/detached=%t", fixture.name, detached), func(t *testing.T) {
				payload := readDocumentCMSFixture(t, fixture, "document.txt")
				name := "attached.der"
				if detached {
					name = "detached.der"
				}
				signature := readDocumentCMSFixture(t, fixture, name)
				request := kalkan.VerifyCMSRequest{
					Signature: kalkan.DER(signature), Detached: detached, SignerID: 1,
					CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
				}
				if detached {
					request.Data = kalkan.Bytes(payload)
				}
				// These historical documents use a TEST signer but a production TSA.
				// Trust in the test CA alone must not authenticate the timestamp.
				javaValidationReject(t, client, request)
				primary := request
				primary.Signature = kalkan.DER(javaCMSWithoutSignatureTimestamp(t, signature))
				javaIntegrationVerify(t, client, primary, payload)
				if tsaClient != nil {
					javaIntegrationVerify(t, tsaClient, request, payload)
				}
			})
		}
	}
}

func TestJavaCMSRequiresTrustedChain(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := openJavaIntegrationClient(t)
	fixture := documentCMSFixtures[0]
	payload := readDocumentCMSFixture(t, fixture, "document.txt")
	request := kalkan.VerifyCMSRequest{
		Signature: kalkan.DER(javaCMSWithoutSignatureTimestamp(t, readDocumentCMSFixture(t, fixture, "attached.der"))),
		SignerID:  1, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
	}
	ctx := context.Background()
	if _, err := client.VerifyCMS(ctx, request); err == nil {
		t.Fatal("CMS verified without a trusted CA")
	}
	if err := client.LoadTrustedCertificate(ctx, kalkan.TrustedCertificate{
		Path: certificatePath(t, assets, "nca_gost2022_test"), Type: kalkan.CertificateIntermediate,
	}); err != nil {
		t.Fatalf("load intermediate certificate: %v", err)
	}
	if _, err := client.VerifyCMS(ctx, request); err == nil {
		t.Fatal("intermediate certificate was accepted as a trust anchor")
	}
	if err := client.LoadTrustedCertificate(ctx, kalkan.TrustedCertificate{
		Path: certificatePath(t, assets, "root_test_gost_2022"), Type: kalkan.CertificateCA,
	}); err != nil {
		t.Fatalf("load trusted CA: %v", err)
	}
	// SkipCertificateTimeCheck must not also skip trust validation in Java.
	javaIntegrationVerify(t, client, request, payload)
}

func TestJavaNativeInterop(t *testing.T) {
	if os.Getenv("KALKANCRYPT_JAVA_PROVIDER") == "" || os.Getenv("KALKANCRYPT_LIBRARY") == "" {
		t.Skip("set KALKANCRYPT_JAVA_PROVIDER and KALKANCRYPT_LIBRARY to run live native interoperability tests")
	}
	assets := loadFixtureAssets(t)
	java := openJavaIntegrationClient(t, javaIntegrationTrust(t, assets)...)
	native := openFixtureClient(t, assets)
	loadJavaIntegrationKeyStore(t, java, assets)
	loadJavaIntegrationKeyStore(t, native, assets)
	ctx := context.Background()
	payload := []byte("Java / native KalkanCrypt compatibility\x00\xff")
	for _, algorithm := range []kalkan.HashAlgorithm{kalkan.SHA256, kalkan.GOST95, kalkan.GOST2015_256, kalkan.GOST2015_512} {
		a, err := java.Hash(ctx, kalkan.HashRequest{Algorithm: algorithm, Data: kalkan.Bytes(payload)})
		if err != nil {
			t.Fatal(err)
		}
		b, err := native.Hash(ctx, kalkan.HashRequest{Algorithm: algorithm, Data: kalkan.Bytes(payload)})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a.Data, b.Data) {
			t.Fatalf("algorithm %d: Java hash %x differs from native %x", algorithm, a.Data, b.Data)
		}
	}
	for _, direction := range []struct {
		name           string
		signer, verify *kalkan.Client
	}{
		{name: "Java-to-native", signer: java, verify: native},
		{name: "native-to-Java", signer: native, verify: java},
	} {
		for _, detached := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/detached=%t", direction.name, detached), func(t *testing.T) {
				signed, err := direction.signer.SignCMS(ctx, kalkan.SignCMSRequest{
					Data: kalkan.Bytes(payload), Detached: detached, IncludeCertificate: true,
					CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
				})
				if err != nil {
					t.Fatalf("SignCMS: %v", err)
				}
				request := kalkan.VerifyCMSRequest{Signature: kalkan.DER(signed.Data), Detached: detached, SignerID: 1, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}
				if detached {
					request.Data = kalkan.Bytes(payload)
				}
				javaIntegrationVerify(t, direction.verify, request, payload)
			})
		}
	}
}

func TestJavaCMSMessageDigestType(t *testing.T) {
	requireJavaValidationProvider(t)
	pki := newJavaValidationPKI(t, "http://unused.invalid")
	client := openJavaIntegrationClient(t, pki.trust(t)...)
	payload := []byte("original signed content")
	javaIntegrationVerify(t, client, kalkan.VerifyCMSRequest{Signature: kalkan.DER(pki.cms(t, payload, "none")), SignerID: 1}, payload)
	for _, incorrect := range []any{"not a digest", 42, true, asn1.ObjectIdentifier{1, 2, 3, 4}} {
		envelope := javaValidationCMS(t, pki.leaf, javaOIDData, payload, nil)
		for i := range envelope.Content.SignerInfos[0].SignedAttributes {
			attribute := &envelope.Content.SignerInfos[0].SignedAttributes[i]
			if attribute.Type.Equal(javaOIDMessageHash) {
				attribute.Values = []asn1.RawValue{{FullBytes: javaValidationASN1(t, incorrect)}}
			}
		}
		javaValidationResign(t, pki.leaf, &envelope.Content.SignerInfos[0], payload)
		// The holder signs malformed attributes once. An attacker then changes
		// the document without re-signing: the SDK must not ignore messageDigest.
		envelope.Content.ContentInfo = asn1.RawValue{FullBytes: javaValidationASN1(t, struct {
			Type asn1.ObjectIdentifier
			Data []byte `asn1:"explicit,tag:0"`
		}{javaOIDData, []byte("attacker replaced the signed content")})}
		if _, err := client.VerifyCMS(t.Context(), kalkan.VerifyCMSRequest{Signature: kalkan.DER(javaValidationASN1(t, envelope)), SignerID: 1}); err == nil {
			t.Errorf("accepted payload substitution with messageDigest value of ASN.1 type %T", incorrect)
		}
	}
}
