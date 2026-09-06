package kalkan

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestClientFixtureCMSCertificateExtraction(t *testing.T) {
	client := openFixtureSigningClient(t)
	ctx := context.Background()
	payload := []byte("certificate extraction from a CMS with distinct signers")
	firstCert, err := client.X509ExportCertificateFromStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.SignCMS(ctx, SignCMSRequest{
		Data: Bytes(payload), IncludeCertificate: true, CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCMSCertificateSources(t, client, first.Data, []*x509.Certificate{firstCert})

	assets := loadFixtureAssets(t)
	if len(assets.P12) < 2 {
		t.Fatal("CMS extraction fixture requires two distinct signing keys")
	}
	if err := client.LoadKeyStore(ctx, KeyStore{Type: PKCS12, Path: assets.P12[1], Password: fixturePassword}); err != nil {
		t.Fatal(err)
	}
	secondCert, err := client.X509ExportCertificateFromStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstCert.Raw, secondCert.Raw) {
		t.Fatal("CMS extraction fixture keys have the same certificate")
	}
	// The low-level API can append a signer to an existing CMS. The public
	// extraction method must return both embedded certificates, in native order.
	native, ok := client.library.(*ckalkan.Client)
	if !ok {
		t.Fatalf("fixture library type = %T, want *ckalkan.Client", client.library)
	}

	second, err := native.SignData(ckalkan.SignDataRequest{
		Data: payload, Signature: first.Data,
		Flags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.OutDER | ckalkan.WithCert | ckalkan.NoCheckCertTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCMSCertificateSources(t, client, second, []*x509.Certificate{firstCert, secondCert})
}

func assertCMSCertificateSources(t *testing.T, client *Client, cms []byte, want []*x509.Certificate) {
	t.Helper()
	for _, tc := range []struct {
		name     string
		data     []byte
		encoding Encoding
	}{
		{"DER", cms, EncodingDER},
		{"PEM", pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: cms}), EncodingPEM},
		{"Base64", []byte(base64.StdEncoding.EncodeToString(cms)), EncodingBase64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "signed.cms")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, source := range []Source{Bytes(tc.data).WithEncoding(tc.encoding), File(path).WithEncoding(tc.encoding)} {
				verified, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
					Signature: source, CertificateTimeCheck: SkipCertificateTimeCheck,
				})
				if err != nil {
					t.Fatalf("positive VerifyCMS: %v", err)
				}
				requireContains(t, "CMS verification", verified.Info, "Verify - OK")
				certs, err := client.GetCertFromCMS(context.Background(), source)
				if err != nil {
					t.Fatalf("GetCertFromCMS(file=%t): %v", source.file, err)
				}
				if len(certs) != len(want) {
					t.Fatalf("signer certificate count = %d, want %d", len(certs), len(want))
				}
				for i, certificate := range certs {
					if !bytes.Equal(certificate.Raw, want[i].Raw) {
						t.Fatalf("signer certificate %d differs from its loaded key", i)
					}
				}
			}
		})
	}
}

func TestClientFixtureXMLCertificateExtraction(t *testing.T) {
	client := openFixtureSigningClient(t)
	ctx := context.Background()
	firstCertificate, err := client.X509ExportCertificateFromStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.SignXML(ctx, SignXMLRequest{
		XML:        Bytes([]byte(`<root><first Id="document1">one</first><second Id="document2">two</second></root>`)),
		SignNodeID: "document1", CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := client.VerifyXML(ctx, VerifyXMLRequest{XML: Bytes(first.XML), CertificateTimeCheck: SkipCertificateTimeCheck})
	if err != nil {
		t.Fatalf("positive VerifyXML: %v", err)
	}
	requireContains(t, "XML verification", verified.Info, "Signature is OK")
	assertXMLCertificates(t, client, first.XML, []*x509.Certificate{firstCertificate})

	assets := loadFixtureAssets(t)
	if len(assets.P12) < 2 {
		t.Fatal("XML extraction fixture requires two distinct signing keys")
	}
	if err := client.LoadKeyStore(ctx, KeyStore{Type: PKCS12, Path: assets.P12[1], Password: fixturePassword}); err != nil {
		t.Fatal(err)
	}
	secondCertificate, err := client.X509ExportCertificateFromStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstCertificate.Raw, secondCertificate.Raw) {
		t.Fatal("XML extraction fixture keys have the same certificate")
	}
	second, err := client.SignXML(ctx, SignXMLRequest{
		XML: Bytes(first.XML), SignNodeID: "document2", CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err = client.VerifyXML(ctx, VerifyXMLRequest{XML: Bytes(second.XML), CertificateTimeCheck: SkipCertificateTimeCheck})
	if err != nil {
		t.Fatalf("positive two-signer VerifyXML: %v", err)
	}
	requireContains(t, "two-signer XML verification", verified.Info, "Signature is OK")
	for _, tc := range []struct {
		name string
		xml  []byte
	}{
		{"sequential IDs", second.XML},
		{"nonconsecutive IDs", bytes.ReplaceAll(bytes.ReplaceAll(second.XML, []byte(`Id="1"`), []byte(`Id="5"`)), []byte(`Id="2"`), []byte(`Id="9"`))},
		{"colliding IDs", bytes.ReplaceAll(bytes.ReplaceAll(bytes.ReplaceAll(second.XML, []byte(`Id="1"`), []byte(`Id="9"`)), []byte(`Id="2"`), []byte(`Id="1"`)), []byte(`Id="9"`), []byte(`Id="2"`))},
		{"no IDs", bytes.ReplaceAll(bytes.ReplaceAll(second.XML, []byte(` Id="1"`), nil), []byte(` Id="2"`), nil)},
		{"internal entity", bytes.Replace(second.XML, []byte(`<root>`), []byte(`<!DOCTYPE root [<!ENTITY label "document">]><root>&label;`), 1)},
		{"legacy encoding", bytes.Replace(bytes.Replace(second.XML, []byte(`encoding="UTF-8"`), []byte(`encoding="ISO-8859-1"`), 1), []byte(`<root>`), []byte("<root>caf\xe9"), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertXMLCertificates(t, client, tc.xml, []*x509.Certificate{firstCertificate, secondCertificate})
		})
	}
}

func assertXMLCertificates(t *testing.T, client *Client, xml []byte, want []*x509.Certificate) {
	t.Helper()
	original := bytes.Clone(xml)
	certificates, err := client.GetCertFromXML(context.Background(), Bytes(xml))
	if err != nil {
		t.Fatalf("GetCertFromXML: %v", err)
	}
	if len(certificates) != len(want) {
		t.Fatalf("signer certificate count = %d, want %d", len(certificates), len(want))
	}
	for i, certificate := range certificates {
		if !bytes.Equal(certificate.Raw, want[i].Raw) {
			t.Fatalf("signer certificate %d differs from its loaded key", i)
		}
	}
	if !bytes.Equal(xml, original) {
		t.Fatal("certificate extraction changed the caller's XML")
	}
}
