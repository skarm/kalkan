package kalkan_test

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/skarm/kalkan"
)

func ExampleOpen() {
	ctx := context.Background()

	client, err := kalkan.Open(ctx,
		kalkan.WithEnvironment(kalkan.TestEnvironment),
		kalkan.WithLibraryPath("/usr/local/lib/libkalkancryptwr-64.so"),
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{
			Path: "/etc/kalkan/certs/root.pem",
			Type: kalkan.CertificateCA,
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	err = client.LoadKeyStore(ctx, kalkan.KeyStore{
		Type:     kalkan.PKCS12,
		Path:     "/etc/kalkan/keys/signing.p12",
		Password: os.Getenv("KALKAN_KEY_PASSWORD"),
		Alias:    "signing-key",
	})
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}
	defer client.Close()
}

func ExampleClient_SignCMS() {
	ctx := context.Background()
	client := openExampleClient(ctx)

	signed, err := client.SignCMS(ctx, kalkan.SignCMSRequest{
		Data:               kalkan.Bytes([]byte("document payload")),
		Detached:           true,
		Timestamp:          true,
		IncludeCertificate: true,
	})
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}
	defer client.Close()

	_ = signed.Data
}

func ExampleClient_VerifyCMS() {
	ctx := context.Background()
	client := openExampleClient(ctx)

	verification, err := client.VerifyCMS(ctx, kalkan.VerifyCMSRequest{
		Signature: kalkan.File("/data/signature.cms").WithEncoding(kalkan.EncodingDER),
		Data:      kalkan.File("/data/document.bin"),
		Detached:  true,
	})
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}
	defer client.Close()

	_ = verification.Valid
	_ = verification.SignerCert
}

func ExampleClient_Hash() {
	ctx := context.Background()
	client := openExampleClient(ctx)

	digest, err := client.Hash(ctx, kalkan.HashRequest{
		Algorithm: kalkan.GOST2015_512,
		Data:      kalkan.File("/data/document.bin"),
	})
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}
	defer client.Close()

	_ = digest.Data
}

func ExampleClient_SignHash() {
	ctx := context.Background()
	client := openExampleClient(ctx)

	digest, err := client.Hash(ctx, kalkan.HashRequest{
		Algorithm: kalkan.GOST2015_512,
		Data:      kalkan.Bytes([]byte("document payload")),
	})
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}

	signed, err := client.SignHash(ctx, kalkan.SignHashRequest{
		Digest:             digest.Data,
		DigestAlgorithm:    digest.Algorithm,
		IncludeCertificate: true,
	})
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}
	defer client.Close()

	_ = signed.Data
}

func ExampleClient_SignXML() {
	ctx := context.Background()
	client := openExampleClient(ctx)

	signed, err := client.SignXML(ctx, kalkan.SignXMLRequest{
		XML:              kalkan.Bytes([]byte(`<root><value>data</value></root>`)),
		Canonicalization: kalkan.XMLCanonicalizationInclusive,
	})
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}
	defer client.Close()

	_ = signed.XML
}

func ExampleClient_SignWSSE() {
	ctx := context.Background()
	client := openExampleClient(ctx)

	signed, err := client.SignWSSE(ctx, kalkan.SignWSSERequest{
		XML:              kalkan.Bytes([]byte(`<m:GetData xmlns:m="urn:example"/>`)),
		BodyID:           "TheBody",
		WrapSOAP:         true,
		Canonicalization: kalkan.XMLCanonicalizationInclusive,
	})
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}
	defer client.Close()

	_ = signed.XML
}

func ExampleClient_SignZIP() {
	ctx := context.Background()
	client := openExampleClient(ctx)

	outputDir, err := os.MkdirTemp("", "kalkan-signzip-*")
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}
	cleanupOutputDir := func() {
		_ = os.RemoveAll(outputDir)
	}

	if err := os.Chmod(outputDir, 0o700); err != nil {
		cleanupOutputDir()
		_ = client.Close()
		log.Fatal(err)
	}

	signed, err := client.SignZIP(ctx, kalkan.SignZIPRequest{
		InputPath:  "/data/document.bin",
		OutputPath: filepath.Join(outputDir, "document.signed.zip"),
	})
	if err != nil {
		cleanupOutputDir()
		_ = client.Close()
		log.Fatal(err)
	}
	defer cleanupOutputDir()
	defer client.Close()

	_ = signed.Path
}

func ExampleClient_VerifyZIP() {
	ctx := context.Background()
	client := openExampleClient(ctx)

	verification, err := client.VerifyZIP(ctx, kalkan.VerifyZIPRequest{
		Path:                    "/data/document.signed.zip",
		ReturnSignerCertificate: true,
	})
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}
	defer client.Close()

	_ = verification.Valid
	_ = verification.SignerCert
}

func ExampleClient_ValidateCertificate() {
	ctx := context.Background()
	client := openExampleClient(ctx)

	certPEM, err := os.ReadFile("/etc/kalkan/certs/user.pem")
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}

	validation, err := client.ValidateCertificate(ctx, kalkan.ValidateCertificateRequest{
		Certificate:        kalkan.PEM(certPEM),
		Mode:               kalkan.CertificateValidationOCSP,
		ReturnOCSPResponse: true,
	})
	if err != nil {
		_ = client.Close()
		log.Fatal(err)
	}
	defer client.Close()

	_ = validation.Valid
	_ = validation.OCSPResponse
}

func openExampleClient(ctx context.Context) *kalkan.Client {
	client, err := kalkan.Open(ctx,
		kalkan.WithEnvironment(kalkan.TestEnvironment),
		kalkan.WithLibraryPath("/usr/local/lib/libkalkancryptwr-64.so"),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := client.LoadKeyStore(ctx, kalkan.KeyStore{
		Type:     kalkan.PKCS12,
		Path:     "/etc/kalkan/keys/signing.p12",
		Password: os.Getenv("KALKAN_KEY_PASSWORD"),
		Alias:    "signing-key",
	}); err != nil {
		_ = client.Close()
		log.Fatal(err)
	}

	return client
}
