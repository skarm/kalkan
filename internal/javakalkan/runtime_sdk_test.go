package javakalkan_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	"github.com/skarm/kalkan"
)

func TestJavaTrustSurvivesKeyStoreLoad(t *testing.T) {
	requireJavaValidationProvider(t)
	pki := newJavaValidationPKI(t, "http://unused.invalid")
	rootPath := javaIntegrationFile(t, "root.der", pki.root.cert.Raw)
	client := openJavaIntegrationClient(t, kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{Type: kalkan.CertificateCA, Path: rootPath}),
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{Type: kalkan.CertificateIntermediate, Data: pki.intermediate.cert.Raw, Format: kalkan.CertificateDER}))
	// Loading a key store preserves loaded trust certificates without rereading their sources.
	if err := os.Remove(rootPath); err != nil {
		t.Fatal(err)
	}
	store := javaValidationKeyStore(t, pki.leaf)
	if err := client.LoadKeyStore(t.Context(), kalkan.KeyStore{Path: store, Password: "test-password"}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("trust is independent of the selected signing key")
	cms, err := client.SignCMS(t.Context(), kalkan.SignCMSRequest{Data: kalkan.Bytes(payload), IncludeCertificate: true})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := client.VerifyCMS(t.Context(), kalkan.VerifyCMSRequest{Signature: kalkan.DER(cms.Data), SignerID: 1})
	if err != nil || !bytes.Equal(verified.Data, payload) {
		t.Fatalf("retained trust verification: %v", err)
	}
}

func TestJavaEndpointPolicyIsAppliedWhenUsed(t *testing.T) {
	requireJavaValidationProvider(t)
	client := openJavaClientWithOptions(t, kalkan.WithEndpointPolicy(kalkan.EndpointPolicy{AllowedHosts: []string{"allowed.invalid"}}))
	if _, err := client.Hash(context.Background(), kalkan.HashRequest{Algorithm: kalkan.SHA256, Data: kalkan.Bytes([]byte("offline hashing"))}); err != nil {
		t.Fatal(err)
	}
}

func TestJavaProviderWithoutXMLDependencies(t *testing.T) {
	t.Setenv("KALKANCRYPT_JAVA_XML_LIBRARIES", "")
	client := openJavaIntegrationClient(t)
	if _, err := client.SignXML(t.Context(), kalkan.SignXMLRequest{XML: kalkan.Bytes([]byte("<document/>"))}); !errors.Is(err, kalkan.ErrJavaUnsupported) {
		t.Fatalf("XML without dependencies: %v", err)
	}
	digest, err := client.Hash(t.Context(), kalkan.HashRequest{Algorithm: kalkan.SHA256, Data: kalkan.Bytes([]byte("abc"))})
	want := sha256.Sum256([]byte("abc"))
	if err != nil || !bytes.Equal(digest.Data, want[:]) {
		t.Fatalf("provider-only hash after XML rejection: %v", err)
	}
}
