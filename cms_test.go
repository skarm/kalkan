package kalkan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestSignCMSUsesRawInputAndReturnsRawCMS(t *testing.T) {
	native := &fakeNative{
		signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
			if alias != "signing-key" {
				t.Fatalf("alias = %q, want signing-key", alias)
			}
			wantFlags := ckalkan.SignCMS | ckalkan.OutDER | ckalkan.DetachedData | ckalkan.WithTimestamp
			if flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, wantFlags)
			}
			if string(data) != "payload" {
				t.Fatalf("native data = %q, want raw payload", data)
			}
			if len(signature) != 0 {
				t.Fatalf("native signature input = %q, want empty", signature)
			}
			return []byte("raw-cms-bytes"), nil
		},
	}
	client := &Client{library: native}

	cms, err := client.SignCMS(context.Background(), SignCMSRequest{
		Alias:     "signing-key",
		Data:      Bytes([]byte("payload")),
		Detached:  true,
		Timestamp: true,
	})
	if err != nil {
		t.Fatalf("SignCMS returned error: %v", err)
	}
	if string(cms.Data) != "raw-cms-bytes" {
		t.Fatalf("CMS data = %q, want raw-cms-bytes", cms.Data)
	}
}

func TestSignCMSIncludesCertificateAndSkipsCertificateTime(t *testing.T) {
	native := &fakeNative{
		signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
			wantFlags := ckalkan.SignCMS | ckalkan.OutDER | ckalkan.WithCert | ckalkan.NoCheckCertTime
			if flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, wantFlags)
			}
			return []byte("raw-cms-with-cert"), nil
		},
	}
	client := &Client{library: native}

	cms, err := client.SignCMS(context.Background(), SignCMSRequest{
		Data:                 Bytes([]byte("payload")),
		IncludeCertificate:   true,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignCMS returned error: %v", err)
	}
	if string(cms.Data) != "raw-cms-with-cert" {
		t.Fatalf("CMS data = %q, want raw-cms-with-cert", cms.Data)
	}
}

func TestSignCMSOutputFormats(t *testing.T) {
	tests := []struct {
		name       string
		format     CMSOutputFormat
		wantFlag   ckalkan.Flag
		wantOutput string
	}{
		{name: "DER", format: CMSOutputDER, wantFlag: ckalkan.OutDER, wantOutput: "raw-cms-output"},
		{name: "base64", format: CMSOutputBase64, wantFlag: ckalkan.OutBase64, wantOutput: "base64-cms-output"},
		{
			name:       "PEM",
			format:     CMSOutputPEM,
			wantFlag:   ckalkan.OutPEM,
			wantOutput: "-----BEGIN CMS-----\n...\n-----END CMS-----\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			native := &fakeNative{
				signDataFunc: func(_ string, flags ckalkan.Flag, _ []byte, _ []byte) ([]byte, error) {
					wantFlags := ckalkan.SignCMS | test.wantFlag
					if flags != wantFlags {
						t.Fatalf("flags = %#x, want %#x", flags, wantFlags)
					}

					return []byte(test.wantOutput), nil
				},
			}
			client := &Client{library: native}

			cms, err := client.SignCMS(context.Background(), SignCMSRequest{
				Data:         Bytes([]byte("payload")),
				OutputFormat: test.format,
			})
			if err != nil {
				t.Fatalf("SignCMS returned error: %v", err)
			}
			if string(cms.Data) != test.wantOutput {
				t.Fatalf("CMS data = %q, want %q", cms.Data, test.wantOutput)
			}
		})
	}
}

func TestSignCMSPassesBase64InputOnlyWhenExplicit(t *testing.T) {
	native := &fakeNative{
		signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
			wantFlags := ckalkan.SignCMS | ckalkan.OutDER | ckalkan.InBase64
			if flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, wantFlags)
			}
			if string(data) != "cGF5bG9hZA==" {
				t.Fatalf("native data = %q, want base64 payload", data)
			}
			return []byte("raw-cms"), nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignCMS(context.Background(), SignCMSRequest{
		Data: Base64([]byte("cGF5bG9hZA==")),
	})
	if err != nil {
		t.Fatalf("SignCMS returned error: %v", err)
	}
}

func TestSignCMSRejectsUnknownOutputFormat(t *testing.T) {
	native := &fakeNative{
		signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
			t.Error("SignCMS called native SignData for an invalid output format")
			return nil, nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignCMS(context.Background(), SignCMSRequest{
		Data:         Bytes([]byte("payload")),
		OutputFormat: CMSOutputFormat(99),
	})
	if err == nil || !strings.Contains(err.Error(), "unknown CMS output format 99") {
		t.Fatalf("SignCMS error = %v, want unknown CMS output format error", err)
	}
}

func TestSignCMSRejectsUnknownDataEncoding(t *testing.T) {
	native := &fakeNative{
		signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
			t.Error("SignCMS called native SignData for an invalid data encoding")
			return nil, nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignCMS(context.Background(), SignCMSRequest{
		Data: Bytes([]byte("payload")).WithEncoding(Encoding(99)),
	})
	if err == nil || !strings.Contains(err.Error(), "unknown encoding 99") {
		t.Fatalf("SignCMS error = %v, want unknown encoding error", err)
	}
}

func TestSignCMSRequiresData(t *testing.T) {
	native := &fakeNative{
		signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
			t.Error("SignCMS called native SignData without Data source")
			return nil, nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignCMS(context.Background(), SignCMSRequest{})
	if err == nil || !strings.Contains(err.Error(), "CMS data is required") {
		t.Fatalf("SignCMS error = %v, want missing CMS data error", err)
	}
}

func TestSignCMSAllowsExplicitEmptyData(t *testing.T) {
	native := &fakeNative{
		signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
			if len(data) != 0 {
				t.Fatalf("native data length = %d, want explicit empty payload", len(data))
			}
			return []byte("raw-empty-cms"), nil
		},
	}
	client := &Client{library: native}

	cms, err := client.SignCMS(context.Background(), SignCMSRequest{
		Data: Bytes([]byte{}),
	})
	if err != nil {
		t.Fatalf("SignCMS returned error: %v", err)
	}
	if string(cms.Data) != "raw-empty-cms" {
		t.Fatalf("CMS data = %q, want raw-empty-cms", cms.Data)
	}
}

func TestVerifyCMSPassesRawSignatureBytesWithoutBase64(t *testing.T) {
	rawSignature := []byte{0x30, 0x82, 0x01, 0x00, 0xff}
	native := &fakeNative{
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			wantFlags := ckalkan.SignCMS | ckalkan.InDER
			if req.Flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", req.Flags, wantFlags)
			}
			if string(req.Signature) != string(rawSignature) {
				t.Fatalf("signature input = %x, want %x", req.Signature, rawSignature)
			}
			if len(req.Data) != 0 {
				t.Fatalf("attached verification data = %q, want empty", req.Data)
			}
			return ckalkan.VerifyDataResult{VerifyInfo: "Verify - OK"}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: Bytes(rawSignature),
	})
	if err != nil {
		t.Fatalf("VerifyCMS returned error: %v", err)
	}
}

func TestVerifyCMSMapsBase64Signature(t *testing.T) {
	native := &fakeNative{
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			wantFlags := ckalkan.SignCMS | ckalkan.InBase64
			if req.Flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", req.Flags, wantFlags)
			}
			if string(req.Signature) != "YmFzZTY0LWNtcw==" {
				t.Fatalf("signature input = %q, want base64 CMS", req.Signature)
			}
			return ckalkan.VerifyDataResult{VerifyInfo: "Verify - OK"}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: Base64([]byte("YmFzZTY0LWNtcw==")),
	})
	if err != nil {
		t.Fatalf("VerifyCMS returned error: %v", err)
	}
}

func TestVerifyCMSPassesRawSignatureFileWithoutBase64Flag(t *testing.T) {
	signaturePath := filepath.Join(t.TempDir(), "raw-signature.cms")
	if err := os.WriteFile(signaturePath, []byte("raw cms"), 0o600); err != nil {
		t.Fatalf("write signature file source: %v", err)
	}

	native := &fakeNative{
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			wantFlags := ckalkan.SignCMS | ckalkan.InFile | ckalkan.InDER
			if req.Flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", req.Flags, wantFlags)
			}
			if string(req.Signature) != signaturePath {
				t.Fatalf("signature input = %q, want raw signature path", req.Signature)
			}
			return ckalkan.VerifyDataResult{VerifyInfo: "Verify - OK"}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: File(signaturePath),
	})
	if err != nil {
		t.Fatalf("VerifyCMS returned error: %v", err)
	}
}

func TestVerifyCMSPassesDetachedFilePathsAndInFileFlag(t *testing.T) {
	dir := t.TempDir()
	signaturePath := filepath.Join(dir, "signature.cms")
	if err := os.WriteFile(signaturePath, []byte("signature cms"), 0o600); err != nil {
		t.Fatalf("write signature file source: %v", err)
	}
	payloadPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(payloadPath, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write payload file source: %v", err)
	}

	native := &fakeNative{
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			wantFlags := ckalkan.SignCMS | ckalkan.InFile | ckalkan.InBase64 | ckalkan.DetachedData | ckalkan.NoCheckCertTime
			if req.Flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", req.Flags, wantFlags)
			}
			if string(req.Signature) != signaturePath {
				t.Fatalf("signature input = %q, want signature path", req.Signature)
			}
			if string(req.Data) != payloadPath {
				t.Fatalf("data input = %q, want detached data path", req.Data)
			}
			return ckalkan.VerifyDataResult{
				VerifyInfo: "Verify - OK",
				Cert:       []byte("signer-cert"),
			}, nil
		},
	}
	client := &Client{library: native}

	verification, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature:            File(signaturePath),
		Data:                 File(payloadPath),
		Detached:             true,
		Encoding:             EncodingBase64,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("VerifyCMS returned error: %v", err)
	}
	if verification.Info != "Verify - OK" {
		t.Fatalf("verification info = %q", verification.Info)
	}
	if string(verification.SignerCert) != "signer-cert" {
		t.Fatalf("signer cert = %q", verification.SignerCert)
	}
}

func TestVerifyCMSDoesNotCopyOutputs(t *testing.T) {
	nativeData := []byte("attached-data")
	nativeCert := []byte("signer-cert")
	client := &Client{library: &fakeNative{
		verifyDataFunc: func(ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			return ckalkan.VerifyDataResult{
				VerifyInfo: "Verify - OK",
				Data:       nativeData,
				Cert:       nativeCert,
			}, nil
		},
	}}

	verification, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: Bytes([]byte("cms")),
	})
	if err != nil {
		t.Fatalf("VerifyCMS returned error: %v", err)
	}
	if !sameByteSliceBacking(verification.Data, nativeData) {
		t.Fatal("VerifyCMS cloned native data output")
	}
	if !sameByteSliceBacking(verification.SignerCert, nativeCert) {
		t.Fatal("VerifyCMS cloned native signer certificate output")
	}
}

func TestVerifyCMSPassesBase64DetachedDataEncoding(t *testing.T) {
	native := &fakeNative{
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			wantFlags := ckalkan.SignCMS | ckalkan.InDER | ckalkan.In2Base64 | ckalkan.DetachedData
			if req.Flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", req.Flags, wantFlags)
			}
			if string(req.Signature) != "raw cms" {
				t.Fatalf("signature = %q, want raw cms", req.Signature)
			}
			if string(req.Data) != "cGF5bG9hZA==" {
				t.Fatalf("detached data = %q, want base64 payload", req.Data)
			}
			return ckalkan.VerifyDataResult{VerifyInfo: "Verify - OK"}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: Bytes([]byte("raw cms")),
		Data:      Base64([]byte("cGF5bG9hZA==")),
		Detached:  true,
	})
	if err != nil {
		t.Fatalf("VerifyCMS returned error: %v", err)
	}
}

func TestVerifyCMSRejectsDetachedDataEncoding(t *testing.T) {
	tests := []struct {
		name string
		data Source
		want string
	}{
		{name: "PEM", data: PEM([]byte("payload")), want: "PEM"},
		{name: "DER", data: DER([]byte("payload")), want: "DER"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			native := &fakeNative{
				verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
					t.Error("VerifyCMS called native VerifyData with unsupported detached data encoding")
					return ckalkan.VerifyDataResult{}, nil
				},
			}
			client := &Client{library: native}

			_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
				Signature: Bytes([]byte("raw cms")),
				Data:      test.data,
				Detached:  true,
			})
			if err == nil || !strings.Contains(err.Error(), "detached CMS data encoding "+test.want+" is not supported") {
				t.Fatalf("VerifyCMS error = %v, want unsupported %s detached data encoding", err, test.want)
			}
		})
	}
}

func TestVerifyCMSRejectsDataForAttachedSignature(t *testing.T) {
	client := &Client{library: &fakeNative{}}

	_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: Bytes([]byte("attached cms")),
		Data:      Bytes([]byte("detached payload")),
	})
	if err == nil || !strings.Contains(err.Error(), "detached CMS data requires detached verification") {
		t.Fatalf("VerifyCMS error = %v, want detached data rejection", err)
	}
}

func TestVerifyCMSRequiresDetachedData(t *testing.T) {
	native := &fakeNative{
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			t.Error("VerifyCMS called native VerifyData without detached data")
			return ckalkan.VerifyDataResult{}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: Bytes([]byte("detached cms")),
		Detached:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "detached CMS data is required") {
		t.Fatalf("VerifyCMS error = %v, want missing detached data rejection", err)
	}
}

func TestVerifyCMSAllowsExplicitEmptyDetachedData(t *testing.T) {
	native := &fakeNative{
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			if len(req.Data) != 0 {
				t.Fatalf("detached data length = %d, want explicit empty payload", len(req.Data))
			}
			return ckalkan.VerifyDataResult{VerifyInfo: "Verify - OK"}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: Bytes([]byte("detached cms")),
		Data:      Bytes([]byte{}),
		Detached:  true,
	})
	if err != nil {
		t.Fatalf("VerifyCMS returned error: %v", err)
	}
}

func TestVerifyCMSRejectsNegativeSignerID(t *testing.T) {
	native := &fakeNative{
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			t.Error("VerifyCMS called native VerifyData for negative SignerID")
			return ckalkan.VerifyDataResult{}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: Bytes([]byte("cms")),
		SignerID:  -1,
	})
	if err == nil || !strings.Contains(err.Error(), "SignerID") {
		t.Fatalf("VerifyCMS error = %v, want SignerID validation error", err)
	}
}

func TestVerifyCMSRejectsSignerIDOverflow(t *testing.T) {
	native := &fakeNative{
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			t.Error("VerifyCMS called native VerifyData for overflowing SignerID")
			return ckalkan.VerifyDataResult{}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: Bytes([]byte("cms")),
		SignerID:  signerIDOverflowValue(t),
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "SignerID") {
		t.Fatalf("VerifyCMS error = %v, want ErrInvalidInput SignerID overflow validation error", err)
	}
}

func TestVerifyCMSAcceptsMaxSignerID(t *testing.T) {
	native := &fakeNative{
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			if req.CertID != maxSignerID {
				t.Fatalf("CertID = %d, want max SignerID %d", req.CertID, maxSignerID)
			}

			return ckalkan.VerifyDataResult{VerifyInfo: "Verify - OK"}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
		Signature: Bytes([]byte("cms")),
		SignerID:  maxSignerID,
	})
	if err != nil {
		t.Fatalf("VerifyCMS returned error: %v", err)
	}
}

func TestVerifyCMSValidatesBeforeNativeLock(t *testing.T) {
	enteredHash := make(chan struct{})
	releaseHash := make(chan struct{})
	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			close(enteredHash)
			<-releaseHash
			return []byte("digest"), nil
		},
	}
	client := &Client{library: native}

	hashDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("payload"))})
		hashDone <- err
	}()
	<-enteredHash

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.VerifyCMS(ctx, VerifyCMSRequest{
		Signature: Bytes([]byte("cms")),
		Encoding:  Encoding(99),
	})
	if err == nil || !strings.Contains(err.Error(), "unknown encoding 99") {
		t.Fatalf("VerifyCMS error = %v, want encoding validation error without waiting for native lock", err)
	}

	close(releaseHash)
	if err := <-hashDone; err != nil {
		t.Fatalf("in-flight Hash returned error: %v", err)
	}
}
