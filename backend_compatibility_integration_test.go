package kalkan

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Both SDKs must agree on which bytes an encoded Source supplies to an operation.
func openBackendCompatibilityClient(t *testing.T, backend string) *Client {
	t.Helper()
	if backend == "native" {
		return openFixtureSigningClient(t)
	}
	provider := os.Getenv("KALKANCRYPT_JAVA_PROVIDER")
	if provider == "" {
		t.Skip("set KALKANCRYPT_JAVA_PROVIDER to run Java backend compatibility tests")
	}
	assets := loadFixtureAssets(t)
	client, err := Open(t.Context(),
		WithJavaProvider(provider), WithJavaExecutable(os.Getenv("KALKANCRYPT_JAVA_EXECUTABLE")),
		WithJavaRevocation(CertificateValidationNone, ""),
		WithTrustedCertificate(TrustedCertificate{Path: certificatePath(t, assets, "root_test_gost_2022"), Type: CertificateCA}),
		WithTrustedCertificate(TrustedCertificate{Path: certificatePath(t, assets, "nca_gost2022_test"), Type: CertificateIntermediate}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := client.LoadKeyStore(t.Context(), KeyStore{Path: keyStorePath(t, assets), Password: fixturePassword}); err != nil {
		t.Fatal(err)
	}
	return client
}

func TestBackendPEMPayloadCompatibility(t *testing.T) {
	for _, backend := range []string{"native", "java"} {
		t.Run(backend, func(t *testing.T) {
			client := openBackendCompatibilityClient(t, backend)
			payload := pem.EncodeToMemory(&pem.Block{Type: "DATA", Bytes: []byte("PEM payload\x00\xff")})
			filename := filepath.Join(t.TempDir(), "payload.pem")
			if err := os.WriteFile(filename, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, input := range []struct {
				name string
				data Source
			}{
				{"memory", PEM(payload)},
				{"file", File(filename).WithEncoding(EncodingPEM)},
			} {
				t.Run(input.name, func(t *testing.T) {
					digest, err := client.Hash(t.Context(), HashRequest{Data: input.data})
					want := sha256.Sum256(payload)
					if err != nil || !bytes.Equal(digest.Data, want[:]) {
						t.Fatalf("Hash(PEM) must hash the entire PEM text: %v", err)
					}
					for _, detached := range []bool{false, true} {
						t.Run(fmt.Sprintf("detached=%t", detached), func(t *testing.T) {
							signed, err := client.SignCMS(t.Context(), SignCMSRequest{
								Data: input.data, Detached: detached, IncludeCertificate: true, CertificateTimeCheck: SkipCertificateTimeCheck,
							})
							if err != nil {
								t.Fatal(err)
							}
							request := VerifyCMSRequest{Signature: DER(signed.Data), Detached: detached, CertificateTimeCheck: SkipCertificateTimeCheck}
							if detached {
								request.Data = Bytes(payload)
							}
							verified, err := client.VerifyCMS(t.Context(), request)
							if err != nil {
								t.Fatalf("CMS must authenticate the entire PEM text: %v", err)
							}
							if !detached && !bytes.Equal(verified.Data, payload) {
								t.Fatal("attached CMS changed the PEM payload")
							}
						})
					}
				})
			}
		})
	}
}
