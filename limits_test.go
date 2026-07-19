package kalkan

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestLimitOptionsUseLastValue(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*config)
		got   func(config) int64
		want  int64
	}{
		{
			name: "max input size",
			apply: func(cfg *config) {
				WithMaxInputSize(123)(cfg)
			},
			got:  func(cfg config) int64 { return cfg.maxInputSize },
			want: 123,
		},
		{
			name: "zero disables max input size",
			apply: func(cfg *config) {
				WithMaxInputSize(123)(cfg)
				WithMaxInputSize(0)(cfg)
			},
			got: func(cfg config) int64 { return cfg.maxInputSize },
		},
		{
			name: "negative disables max input size",
			apply: func(cfg *config) {
				WithMaxInputSize(123)(cfg)
				WithMaxInputSize(-1)(cfg)
			},
			got: func(cfg config) int64 { return cfg.maxInputSize },
		},
		{
			name: "max output buffer size",
			apply: func(cfg *config) {
				WithMaxOutputBufferSize(456)(cfg)
			},
			got:  func(cfg config) int64 { return int64(cfg.maxOutputBufferSize) },
			want: 456,
		},
		{
			name: "zero disables max output buffer size",
			apply: func(cfg *config) {
				WithMaxOutputBufferSize(456)(cfg)
				WithMaxOutputBufferSize(0)(cfg)
			},
			got: func(cfg config) int64 { return int64(cfg.maxOutputBufferSize) },
		},
		{
			name: "negative disables max output buffer size",
			apply: func(cfg *config) {
				WithMaxOutputBufferSize(456)(cfg)
				WithMaxOutputBufferSize(-1)(cfg)
			},
			got: func(cfg config) int64 { return int64(cfg.maxOutputBufferSize) },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := defaultOpenConfig()
			test.apply(&cfg)
			if got := test.got(cfg); got != test.want {
				t.Fatalf("configured limit = %d, want %d", got, test.want)
			}
		})
	}
}

func TestMaxInputSizeRejectsMemorySources(t *testing.T) {
	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			t.Error("Hash called native with oversized memory input")
			return nil, nil
		},
		signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
			t.Error("CMS called native with oversized memory input")
			return nil, nil
		},
		signHashFunc: func(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error) {
			t.Error("SignHash called native with oversized digest input")
			return nil, nil
		},
		signXMLFunc: func(req ckalkan.SignXMLRequest) ([]byte, error) {
			t.Error("SignXML called native with oversized memory input")
			return nil, nil
		},
		signWSSEFunc: func(req ckalkan.SignWSSERequest) ([]byte, error) {
			t.Error("SignWSSE called native with oversized wrapped XML input")
			return nil, nil
		},
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			t.Error("ValidateCertificate called native with oversized memory input")
			return ckalkan.ValidateCertificateResult{}, nil
		},
		loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
			t.Error("LoadTrustedCertificate called native with oversized certificate data")
			return nil
		},
		certificateGetInfoFunc: func(cert []byte, prop ckalkan.CertProp) ([]byte, error) {
			t.Error("X509CertificateGetInfo called native with oversized certificate data")
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
			t.Error("SignWSSE called native with oversized wrapped XML input")
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
