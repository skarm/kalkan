package kalkan

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

const (
	benchmarkSmallPayloadSize = 1 << 10
	benchmarkLargePayloadSize = 8 << 20
)

var (
	benchmarkDigestOutput = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	benchmarkCMSOutput  = []byte("cms")
	benchmarkXMLOutput  = []byte("<signed/>")
	benchmarkVerifyInfo = "Verify - OK"
	benchmarkZIPCert    = []byte("zip-cert")

	benchmarkDigestSink     *Digest
	benchmarkCMSSink        *CMS
	benchmarkSignedXMLSink  *SignedXML
	benchmarkVerifySink     *Verification
	benchmarkZIPSink        *ZIPVerification
	benchmarkValidationSink *CertificateValidation
	benchmarkSourceSink     Source
)

var errBenchmarkNativeStop = errors.New("benchmark native stop")

func BenchmarkHashBytesSmall(b *testing.B) {
	client := benchmarkClient()
	payload := benchmarkPayload(benchmarkSmallPayloadSize)
	ctx := context.Background()

	if _, err := client.Hash(ctx, HashRequest{Data: Bytes(payload)}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		digest, err := client.Hash(ctx, HashRequest{Data: Bytes(payload)})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkDigestSink = digest
	}
}

func BenchmarkHashBytesLarge(b *testing.B) {
	client := benchmarkClient()
	payload := benchmarkPayload(benchmarkLargePayloadSize)
	ctx := context.Background()

	if _, err := client.Hash(ctx, HashRequest{Data: Bytes(payload)}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		digest, err := client.Hash(ctx, HashRequest{Data: Bytes(payload)})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkDigestSink = digest
	}
}

func BenchmarkHashPrebuiltSourceLarge(b *testing.B) {
	client := benchmarkClient()
	payload := benchmarkPayload(benchmarkLargePayloadSize)
	source := Bytes(payload)
	ctx := context.Background()

	if _, err := client.Hash(ctx, HashRequest{Data: source}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		digest, err := client.Hash(ctx, HashRequest{Data: source})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkDigestSink = digest
	}
}

func BenchmarkHashFileLarge(b *testing.B) {
	client := benchmarkClient()
	payload := benchmarkPayload(benchmarkLargePayloadSize)
	path := benchmarkWriteFile(b, "payload.bin", payload)
	ctx := context.Background()

	if _, err := client.Hash(ctx, HashRequest{Data: File(path)}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		digest, err := client.Hash(ctx, HashRequest{Data: File(path)})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkDigestSink = digest
	}
}

func BenchmarkSignCMSSourceBytes(b *testing.B) {
	client := benchmarkClient()
	payload := benchmarkPayload(benchmarkLargePayloadSize)
	ctx := context.Background()

	if _, err := client.SignCMS(ctx, SignCMSRequest{Data: Bytes(payload)}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		cms, err := client.SignCMS(ctx, SignCMSRequest{Data: Bytes(payload)})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkCMSSink = cms
	}
}

func BenchmarkSignCMSPrebuiltSourceBytes(b *testing.B) {
	client := benchmarkClient()
	payload := benchmarkPayload(benchmarkLargePayloadSize)
	source := Bytes(payload)
	ctx := context.Background()

	if _, err := client.SignCMS(ctx, SignCMSRequest{Data: source}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		cms, err := client.SignCMS(ctx, SignCMSRequest{Data: source})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkCMSSink = cms
	}
}

func BenchmarkVerifyCMSDetachedBytes(b *testing.B) {
	client := benchmarkClient()
	signature := benchmarkPayload(4 << 10)
	payload := benchmarkPayload(benchmarkLargePayloadSize)
	ctx := context.Background()

	if _, err := client.VerifyCMS(ctx, VerifyCMSRequest{
		Signature: Bytes(signature),
		Data:      Bytes(payload),
		Detached:  true,
	}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(signature) + len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		verification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
			Signature: Bytes(signature),
			Data:      Bytes(payload),
			Detached:  true,
		})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkVerifySink = verification
	}
}

func BenchmarkVerifyCMSDetachedFile(b *testing.B) {
	client := benchmarkClient()
	signature := benchmarkPayload(4 << 10)
	payload := benchmarkPayload(benchmarkLargePayloadSize)
	signaturePath := benchmarkWriteFile(b, "signature.cms", signature)
	payloadPath := benchmarkWriteFile(b, "payload.bin", payload)
	ctx := context.Background()

	if _, err := client.VerifyCMS(ctx, VerifyCMSRequest{
		Signature: File(signaturePath),
		Data:      File(payloadPath),
		Detached:  true,
	}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(signature) + len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		verification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
			Signature: File(signaturePath),
			Data:      File(payloadPath),
			Detached:  true,
		})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkVerifySink = verification
	}
}

func BenchmarkSignXMLWrapSOAP(b *testing.B) {
	client := benchmarkClient()
	payload := []byte(`<payload><name>test</name><value>123</value></payload>`)
	ctx := context.Background()

	if _, err := client.SignWSSE(ctx, SignWSSERequest{
		XML:      Bytes(payload),
		BodyID:   "body",
		WrapSOAP: true,
	}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		signed, err := client.SignWSSE(ctx, SignWSSERequest{
			XML:      Bytes(payload),
			BodyID:   "body",
			WrapSOAP: true,
		})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkSignedXMLSink = signed
	}
}

func BenchmarkValidateCertificatePEM(b *testing.B) {
	client := benchmarkClient()
	cert := benchmarkPayload(2 << 10)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	ctx := context.Background()

	if _, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
		Certificate: PEM(certPEM),
		Mode:        CertificateValidationNone,
	}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(certPEM)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		validation, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
			Certificate: PEM(certPEM),
			Mode:        CertificateValidationNone,
		})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkValidationSink = validation
	}
}

func BenchmarkValidateCertificateBase64(b *testing.B) {
	client := benchmarkClient()
	cert := benchmarkPayload(2 << 10)
	certBase64 := []byte(base64.StdEncoding.EncodeToString(cert))
	ctx := context.Background()

	if _, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
		Certificate: Base64(certBase64),
		Mode:        CertificateValidationNone,
	}); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(certBase64)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		validation, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
			Certificate: Base64(certBase64),
			Mode:        CertificateValidationNone,
		})
		if err != nil {
			b.Fatal(err)
		}

		benchmarkValidationSink = validation
	}
}

func BenchmarkSourceBytesAllocations(b *testing.B) {
	payload := benchmarkPayload(benchmarkLargePayloadSize)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		benchmarkSourceSink = Bytes(payload)
	}
}

func TestGoSideAllocsPerRun(t *testing.T) {
	client := preNativeBenchmarkClient()
	ctx := context.Background()
	payload := benchmarkPayload(4 << 10)
	digest := benchmarkPayload(64)
	cert := benchmarkPayload(2 << 10)
	certBase64 := []byte("Y2VydA==")

	cases := []struct {
		name      string
		maxAllocs float64
		run       func() error
	}{
		{
			name:      "Bytes(data) -> SignCMS",
			maxAllocs: 2,
			run: func() error {
				_, err := client.SignCMS(ctx, SignCMSRequest{Data: Bytes(payload)})
				return err
			},
		},
		{
			name:      "Bytes(data) -> Hash",
			maxAllocs: 2,
			run: func() error {
				_, err := client.Hash(ctx, HashRequest{Data: Bytes(payload)})
				return err
			},
		},
		{
			name:      "SignHash",
			maxAllocs: 2,
			run: func() error {
				_, err := client.SignHash(ctx, SignHashRequest{
					Digest:          digest,
					DigestAlgorithm: GOST2015_512,
				})
				return err
			},
		},
		{
			name:      "ValidateCertificate with DER",
			maxAllocs: 2,
			run: func() error {
				_, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
					Certificate: DER(cert),
					Mode:        CertificateValidationNone,
				})
				return err
			},
		},
		{
			name:      "ValidateCertificate with base64",
			maxAllocs: 4,
			run: func() error {
				_, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
					Certificate: Base64(certBase64),
					Mode:        CertificateValidationNone,
				})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, errBenchmarkNativeStop) {
				t.Fatalf("run error = %v, want %v", err, errBenchmarkNativeStop)
			}

			allocs := testing.AllocsPerRun(100, func() {
				_ = tc.run()
			})
			t.Logf("%.2f allocs/run", allocs)
			if allocs > tc.maxAllocs {
				t.Fatalf("allocs/run = %.2f, want <= %.2f", allocs, tc.maxAllocs)
			}
		})
	}
}

func benchmarkClient() *Client {
	return &Client{
		library: &fakeNative{
			hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
				return benchmarkDigestOutput, nil
			},
			signHashFunc: func(string, ckalkan.Flag, []byte) ([]byte, error) {
				return benchmarkCMSOutput, nil
			},
			signDataFunc: func(string, ckalkan.Flag, []byte, []byte) ([]byte, error) {
				return benchmarkCMSOutput, nil
			},
			verifyDataFunc: func(ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
				return ckalkan.VerifyDataResult{VerifyInfo: benchmarkVerifyInfo}, nil
			},
			signXMLFunc: func(ckalkan.SignXMLRequest) ([]byte, error) {
				return benchmarkXMLOutput, nil
			},
			signWSSEFunc: func(ckalkan.SignWSSERequest) ([]byte, error) {
				return benchmarkXMLOutput, nil
			},
			validateCertificateFunc: func(ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
				return ckalkan.ValidateCertificateResult{Info: benchmarkVerifyInfo}, nil
			},
			zipConVerifyFunc: func(string, ckalkan.Flag) (string, error) {
				return benchmarkVerifyInfo, nil
			},
			getCertFromZipFileFunc: func(string, ckalkan.Flag, int) ([]byte, error) {
				return benchmarkZIPCert, nil
			},
		},
	}
}

func preNativeBenchmarkClient() *Client {
	return &Client{
		library: &fakeNative{
			hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
				return nil, errBenchmarkNativeStop
			},
			signHashFunc: func(string, ckalkan.Flag, []byte) ([]byte, error) {
				return nil, errBenchmarkNativeStop
			},
			signDataFunc: func(string, ckalkan.Flag, []byte, []byte) ([]byte, error) {
				return nil, errBenchmarkNativeStop
			},
			validateCertificateFunc: func(ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
				return ckalkan.ValidateCertificateResult{}, errBenchmarkNativeStop
			},
		},
	}
}

func benchmarkWriteFile(b *testing.B, name string, data []byte) string {
	b.Helper()

	path := filepath.Join(b.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		b.Fatal(err)
	}

	return path
}

func benchmarkPayload(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i)
	}

	return data
}
