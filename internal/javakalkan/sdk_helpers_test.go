// Package javakalkan_test exercises the public API against the actual SDK provider.
// KALKANCRYPT_JAVA_PROVIDER opts in; XML tests also need
// KALKANCRYPT_JAVA_XML_LIBRARIES. Revocation and TSA tests use local responders.
package javakalkan_test

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/internal/testfixture"
)

func requireJavaValidationProvider(t *testing.T) {
	t.Helper()
	if os.Getenv("KALKANCRYPT_JAVA_PROVIDER") == "" {
		t.Skip("set KALKANCRYPT_JAVA_PROVIDER to run local Java validation integration tests")
	}
}

func javaValidationReject(t *testing.T, client *kalkan.Client, request kalkan.VerifyCMSRequest) {
	t.Helper()
	if result, err := client.VerifyCMS(context.Background(), request); err == nil {
		t.Fatalf("invalid CMS validation succeeded: %#v", result)
	} else {
		var providerError *kalkan.JavaError
		if !errors.As(err, &providerError) {
			t.Fatalf("validation failed outside the Java verifier: %v", err)
		}
	}
}

func javaCMSWithoutSignatureTimestamp(t *testing.T, der []byte) []byte {
	t.Helper()
	var envelope testfixture.CMSEnvelope
	if rest, err := asn1.Unmarshal(der, &envelope); err != nil || len(rest) != 0 {
		t.Fatalf("parse fixture CMS: %v", err)
	}
	removed := 0
	for i := range envelope.Content.SignerInfos {
		signer := &envelope.Content.SignerInfos[i]
		var retained []testfixture.CMSAttribute
		for _, attribute := range signer.UnsignedAttributes {
			if attribute.Type.Equal(javaOIDTimestamp) {
				removed++
			} else {
				retained = append(retained, attribute)
			}
		}
		signer.UnsignedAttributes = retained
	}
	if removed == 0 {
		t.Fatal("expected a production timestamp in historical CMS fixture")
	}
	return javaValidationASN1(t, envelope)
}

func openJavaIntegrationClient(t *testing.T, options ...kalkan.Option) *kalkan.Client {
	t.Helper()
	// The historical algorithm/encoding fixtures have no live revocation service.
	// Dedicated validation tests use local OCSP/CRL responders.
	options = append([]kalkan.Option{kalkan.WithJavaRevocation(kalkan.CertificateValidationNone, "")}, options...)
	return openJavaClientWithOptions(t, options...)
}

func openJavaClientWithOptions(t *testing.T, options ...kalkan.Option) *kalkan.Client {
	t.Helper()
	provider := os.Getenv("KALKANCRYPT_JAVA_PROVIDER")
	if provider == "" {
		t.Skip("set KALKANCRYPT_JAVA_PROVIDER to run SDK Java integration tests")
	}
	options = append(options, kalkan.WithJavaProvider(provider))
	if libraries := os.Getenv("KALKANCRYPT_JAVA_XML_LIBRARIES"); libraries != "" {
		options = append(options, kalkan.WithJavaXMLLibraries(filepath.SplitList(libraries)...))
	}
	if executable := os.Getenv("KALKANCRYPT_JAVA_EXECUTABLE"); executable != "" {
		options = append(options, kalkan.WithJavaExecutable(executable))
	}
	client, err := kalkan.Open(context.Background(), options...)
	if err != nil {
		t.Fatalf("Open Java backend: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close Java backend: %v", err)
		}
	})
	return client
}

func javaIntegrationTrust(t *testing.T, assets fixtureAssets) []kalkan.Option {
	t.Helper()
	return []kalkan.Option{
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{Path: certificatePath(t, assets, "root_test_gost_2022"), Type: kalkan.CertificateCA}),
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{Path: certificatePath(t, assets, "nca_gost2022_test"), Type: kalkan.CertificateIntermediate}),
	}
}

func loadJavaIntegrationKeyStore(t *testing.T, client *kalkan.Client, assets fixtureAssets) {
	t.Helper()
	if err := client.LoadKeyStore(context.Background(), kalkan.KeyStore{Type: kalkan.PKCS12, Path: keyStorePath(t, assets), Password: fixturePassword}); err != nil {
		t.Fatalf("LoadKeyStore: %v", err)
	}
}

func javaIntegrationFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func javaIntegrationCMSDER(t *testing.T, data []byte, format kalkan.CMSOutputFormat) []byte {
	t.Helper()
	switch format {
	case kalkan.CMSOutputBase64:
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			t.Fatalf("CMS output is not base64: %v", err)
		}
		return decoded
	case kalkan.CMSOutputPEM:
		block, rest := pem.Decode(data)
		if block == nil || (block.Type != "CMS" && block.Type != "PKCS7") || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatal("CMS output is not a single CMS/PKCS7 PEM block")
		}
		return block.Bytes
	default:
		return data
	}
}

func javaIntegrationVerify(t *testing.T, client *kalkan.Client, request kalkan.VerifyCMSRequest, wantPayload []byte) {
	t.Helper()
	verified, err := client.VerifyCMS(context.Background(), request)
	if err != nil || verified == nil {
		t.Fatalf("VerifyCMS = %#v, %v", verified, err)
	}
	if request.Detached {
		wantPayload = nil
	}
	if !bytes.Equal(verified.Data, wantPayload) {
		t.Fatalf("verified payload = %x, want %x", verified.Data, wantPayload)
	}
	if verified.Info == "" || len(verified.SignerCert) == 0 {
		t.Fatal("VerifyCMS omitted verification information or signer certificate")
	}
}

func openFixtureClient(t *testing.T, assets fixtureAssets) *kalkan.Client {
	t.Helper()

	library := strings.TrimSpace(os.Getenv("KALKANCRYPT_LIBRARY"))
	if library == "" {
		t.Skip("set KALKANCRYPT_LIBRARY to run native-backed root API tests")
	}

	client, err := kalkan.Open(context.Background(),
		kalkan.WithLibraryPath(library),
		kalkan.WithTSAURL(testTSAURL),
		kalkan.WithOCSPURL(testOCSPURL),
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{
			Path: certificatePath(t, assets, "root_test_gost_2022"),
			Type: kalkan.CertificateCA,
		}),
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{
			Path: certificatePath(t, assets, "nca_gost2022_test"),
			Type: kalkan.CertificateIntermediate,
		}),
	)
	if errors.Is(err, ckalkan.ErrUnavailable) {
		t.Skip("native-backed root API tests require Linux with cgo enabled")
	}
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	})

	return client
}

func keyStorePath(t *testing.T, assets fixtureAssets) string {
	t.Helper()

	for _, path := range assets.P12 {
		if strings.Contains(filepath.Base(path), "___Valid_") {
			return path
		}
	}
	if len(assets.P12) == 0 {
		t.Skip("no PKCS#12 fixtures found")
	}

	return assets.P12[0]
}

func certificatePath(t *testing.T, assets fixtureAssets, name string) string {
	t.Helper()

	path := assets.Certs[name]
	if path == "" {
		t.Fatalf("fixture certificate %q not found", name)
	}

	return path
}

const (
	fixturePassword = "Qwerty12"
	testTSAURL      = "http://test.pki.gov.kz/tsp/"
	testOCSPURL     = "http://test.pki.gov.kz/ocsp/"
)

type fixtureAssets = testfixture.SDKAssets

func fixturePath(parts ...string) string {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		panic("cannot locate SDK fixtures")
	}
	return filepath.Join(append([]string{filepath.Dir(source), "..", "..", "testdata"}, parts...)...)
}

func loadFixtureAssets(t *testing.T) fixtureAssets {
	t.Helper()
	return testfixture.LoadSDK(t, fixturePath())
}

type documentCMSFixture struct{ name string }

var documentCMSFixtures = []documentCMSFixture{{name: "legal_entity"}, {name: "individual"}}

func readDocumentCMSFixture(t *testing.T, fixture documentCMSFixture, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(fixturePath("cms", fixture.name+"_"+name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
