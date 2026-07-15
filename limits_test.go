package kalkan

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestMaxInputSizeOptionsOverrideConfig(t *testing.T) {
	cfg := defaultOpenConfig()
	WithMaxInputSize(123)(&cfg)

	if cfg.maxInputSize != 123 {
		t.Fatalf("max input size = %d, want 123", cfg.maxInputSize)
	}
}

func TestMaxInputSizeRejectsMemorySources(t *testing.T) {
	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			t.Fatal("Hash called native with oversized memory input")
			return nil, nil
		},
		signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
			t.Fatal("CMS called native with oversized memory input")
			return nil, nil
		},
		signHashFunc: func(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error) {
			t.Fatal("SignHash called native with oversized digest input")
			return nil, nil
		},
		signXMLFunc: func(req ckalkan.SignXMLRequest) ([]byte, error) {
			t.Fatal("SignXML called native with oversized memory input")
			return nil, nil
		},
		signWSSEFunc: func(req ckalkan.SignWSSERequest) ([]byte, error) {
			t.Fatal("SignWSSE called native with oversized wrapped XML input")
			return nil, nil
		},
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			t.Fatal("ValidateCertificate called native with oversized memory input")
			return ckalkan.ValidateCertificateResult{}, nil
		},
		loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
			t.Fatal("LoadTrustedCertificate called native with oversized certificate data")
			return nil
		},
		certificateGetInfoFunc: func(cert []byte, prop ckalkan.CertProp) ([]byte, error) {
			t.Fatal("X509CertificateGetInfo called native with oversized certificate data")
			return nil, nil
		},
	}
	client := &Client{library: native, config: runtimeConfig{maxInputSize: 3}}
	cert, err := x509.ParseCertificate(testCertificateDER(t, "Max Input Test"))
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "Hash",
			call: func() error {
				_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("1234"))})
				return err
			},
		},
		{
			name: "SignHash",
			call: func() error {
				_, err := client.SignHash(context.Background(), SignHashRequest{Digest: []byte("1234")})
				return err
			},
		},
		{
			name: "SignCMS",
			call: func() error {
				_, err := client.SignCMS(context.Background(), SignCMSRequest{Data: Bytes([]byte("1234"))})
				return err
			},
		},
		{
			name: "VerifyCMS",
			call: func() error {
				_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{Signature: Bytes([]byte("1234"))})
				return err
			},
		},
		{
			name: "SignXML",
			call: func() error {
				_, err := client.SignXML(context.Background(), SignXMLRequest{XML: Bytes([]byte("<a/>"))})
				return err
			},
		},
		{
			name: "ValidateCertificate",
			call: func() error {
				_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
					Certificate: DER([]byte("1234")),
					Mode:        CertificateValidationNone,
				})
				return err
			},
		},
		{
			name: "LoadTrustedCertificate",
			call: func() error {
				return client.LoadTrustedCertificate(context.Background(), TrustedCertificate{
					Data:   []byte("1234"),
					Type:   CertificateCA,
					Format: CertificateDER,
				})
			},
		},
		{
			name: "X509CertificateGetInfo",
			call: func() error {
				_, err := client.X509CertificateGetInfo(context.Background(), cert)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if err == nil || !strings.Contains(err.Error(), "maximum input size of 3 bytes") {
				t.Fatalf("%s error = %v, want max input size rejection", test.name, err)
			}
		})
	}
}

func TestMaxInputSizeRejectsWrappedWSSE(t *testing.T) {
	native := &fakeNative{
		signWSSEFunc: func(req ckalkan.SignWSSERequest) ([]byte, error) {
			t.Fatal("SignWSSE called native with oversized wrapped XML input")
			return nil, nil
		},
	}
	client := &Client{library: native, config: runtimeConfig{maxInputSize: 10}}

	_, err := client.SignWSSE(context.Background(), SignWSSERequest{
		XML:      Bytes([]byte("<a/>")),
		BodyID:   "body",
		WrapSOAP: true,
	})
	if err == nil || !strings.Contains(err.Error(), "maximum input size of 10 bytes") {
		t.Fatalf("SignWSSE error = %v, want wrapped XML max input size rejection", err)
	}
}

func TestMaxInputSizeAllowsFileSources(t *testing.T) {
	path := writeTestFile(t, t.TempDir(), "payload.txt", []byte("1234"))
	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			if string(data) != path {
				t.Fatalf("Hash data = %q, want file path %q", data, path)
			}

			return []byte("digest"), nil
		},
	}
	client := &Client{library: native, config: runtimeConfig{maxInputSize: 3}}

	if _, err := client.Hash(context.Background(), HashRequest{Data: File(path)}); err != nil {
		t.Fatalf("Hash returned error for file source: %v", err)
	}
}
