package ckalkan

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestSingleBufferMethodsRetryWithReportedLength(t *testing.T) {
	tests := []struct {
		name    string
		install func(*fakeNativeContext, *[]int)
		call    func(*Client) error
	}{
		{
			name: "HashData",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.hashDataFunc = func(call kalkancrypt.HashDataCall) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, call.Capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.HashData(SHA256, 0, []byte("data"))
				return err
			},
		},
		{
			name: "SignHash",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.signHashFunc = func(call kalkancrypt.SignHashCall) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, call.Capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.SignHash("alias", 0, []byte("hash"))
				return err
			},
		},
		{
			name: "SignData",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.signDataFunc = func(call kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, call.Capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.SignData(SignDataRequest{Flags: SignCMS, Data: []byte("data")})
				return err
			},
		},
		{
			name: "SignXML",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.signXMLFunc = func(call kalkancrypt.SignXMLCall) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, call.Capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.SignXML(SignXMLRequest{XML: []byte("<root/>")})
				return err
			},
		},
		{
			name: "SignWSSE",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.signWSSEFunc = func(call kalkancrypt.SignWSSECall) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, call.Capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.SignWSSE(SignWSSERequest{XML: []byte("<root/>")})
				return err
			},
		},
		{
			name: "VerifyXML",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.verifyXMLFunc = func(call kalkancrypt.VerifyXMLCall) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, call.Capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.VerifyXML("", 0, []byte("<root/>"))
				return err
			},
		},
		{
			name: "GetCertFromXML",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.getCertFromXMLFunc = func(_ []byte, _, capacity int) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.GetCertFromXML([]byte("<root/>"), 0)
				return err
			},
		},
		{
			name: "GetSigAlgFromXML",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.getSigAlgFromXMLFunc = func(_ []byte, capacity int) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.GetSigAlgFromXML([]byte("<root/>"))
				return err
			},
		},
		{
			name: "GetCertFromCMS",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.getCertFromCMSFunc = func(call kalkancrypt.GetCertFromCMSCall) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, call.Capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.GetCertFromCMS([]byte("cms"), 0, 0)
				return err
			},
		},
		{
			name: "ZipConVerify",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.zipConVerifyFunc = func(_ string, _, capacity int) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.ZipConVerify("signed.zip", 0)
				return err
			},
		},
		{
			name: "GetCertFromZipFile",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.getCertFromZipFileFunc = func(call kalkancrypt.GetCertFromZipFileCall) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, call.Capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.GetCertFromZipFile("signed.zip", 0, 0)
				return err
			},
		},
		{
			name: "X509ExportCertificateFromStore",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.x509ExportFunc = func(_ string, _, capacity int) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.X509ExportCertificateFromStore("alias", CertDER)
				return err
			},
		},
		{
			name: "X509CertificateGetInfo",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.x509InfoFunc = func(_ []byte, _, capacity int) (kalkancrypt.BufferResult, error) {
					return bufferTooSmallOnce(capacities, capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.X509CertificateGetInfo([]byte("cert"), CertPropSubjectCommonName)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &fakeNativeContext{}
			var capacities []int
			test.install(ctx, &capacities)
			client := &Client{ctx: ctx, config: defaultConfig()}

			if err := test.call(client); err != nil {
				t.Fatalf("%s failed: %v", test.name, err)
			}
			if len(capacities) != 2 {
				t.Fatalf("capacities = %v, want two attempts", capacities)
			}
			if capacities[1] != capacities[0]+11 {
				t.Fatalf("capacities = %v, want reported second capacity %d", capacities, capacities[0]+11)
			}
		})
	}
}

func TestListMethodsRetryAfterBufferTooSmall(t *testing.T) {
	tests := []struct {
		name    string
		install func(*fakeNativeContext, *[]int)
		call    func(*Client) error
	}{
		{
			name: "GetTokens",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.getTokensFunc = func(_ uint64, capacity int) (kalkancrypt.ListResult, error) {
					return listBufferTooSmallOnce(capacities, capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.GetTokens(StorePKCS12)
				return err
			},
		},
		{
			name: "GetCertificatesList",
			install: func(ctx *fakeNativeContext, capacities *[]int) {
				ctx.getCertificatesListFunc = func(capacity int) (kalkancrypt.ListResult, error) {
					return listBufferTooSmallOnce(capacities, capacity)
				}
			},
			call: func(client *Client) error {
				_, err := client.GetCertificatesList()
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &fakeNativeContext{}
			var capacities []int
			test.install(ctx, &capacities)
			client := &Client{ctx: ctx, config: defaultConfig()}

			if err := test.call(client); err != nil {
				t.Fatalf("%s failed: %v", test.name, err)
			}
			if want := []int{defaultListBufferSize, defaultListBufferSize * 2}; !slices.Equal(capacities, want) {
				t.Fatalf("capacities = %v, want %v", capacities, want)
			}
		})
	}
}

func TestOutputMethodsRejectInvalidNativeLengths(t *testing.T) {
	t.Run("single output", func(t *testing.T) {
		client := &Client{config: defaultConfig()}
		_, err := client.callBufferWithCapacityLocked(defaultOutputBufferSize, func(int) (kalkancrypt.BufferResult, error) {
			return kalkancrypt.BufferResult{Code: uint64(ErrorOK), OutLen: -1}, nil
		})
		if err == nil || !strings.Contains(err.Error(), "negative") {
			t.Fatalf("error = %v, want negative native length", err)
		}
	})

	t.Run("single output length mismatch", func(t *testing.T) {
		client := &Client{config: defaultConfig()}
		_, err := client.callBufferWithCapacityLocked(defaultOutputBufferSize, func(int) (kalkancrypt.BufferResult, error) {
			return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("x"), OutLen: 2}, nil
		})
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("error = %v, want inconsistent native length", err)
		}
	})

	t.Run("VerifyData", func(t *testing.T) {
		ctx := &fakeNativeContext{
			verifyDataFunc: func(kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
				return kalkancrypt.VerifyResult{Code: uint64(ErrorOK), InfoLen: -1}, nil
			},
		}
		client := &Client{ctx: ctx, config: defaultConfig()}
		_, err := client.VerifyData(VerifyDataRequest{Flags: SignCMS})
		if err == nil || !strings.Contains(err.Error(), "negative") {
			t.Fatalf("error = %v, want negative native length", err)
		}
	})

	t.Run("VerifyData length mismatch", func(t *testing.T) {
		ctx := &fakeNativeContext{
			verifyDataFunc: func(kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
				return kalkancrypt.VerifyResult{Code: uint64(ErrorOK), Info: []byte("x"), InfoLen: 2}, nil
			},
		}
		client := &Client{ctx: ctx, config: defaultConfig()}
		_, err := client.VerifyData(VerifyDataRequest{Flags: SignCMS})
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("error = %v, want inconsistent native length", err)
		}
	})

	t.Run("X509ValidateCertificate", func(t *testing.T) {
		ctx := &fakeNativeContext{
			validateCertificateFunc: func(kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
				return kalkancrypt.ValidateResult{Code: uint64(ErrorOK), OCSPLen: -1}, nil
			},
		}
		client := &Client{ctx: ctx, config: defaultConfig()}
		_, err := client.X509ValidateCertificate(ValidateCertificateRequest{})
		if err == nil || !strings.Contains(err.Error(), "negative") {
			t.Fatalf("error = %v, want negative native length", err)
		}
	})

	t.Run("X509ValidateCertificate length mismatch", func(t *testing.T) {
		ctx := &fakeNativeContext{
			validateCertificateFunc: func(kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
				return kalkancrypt.ValidateResult{Code: uint64(ErrorOK), OCSP: []byte("x"), OCSPLen: 2}, nil
			},
		}
		client := &Client{ctx: ctx, config: defaultConfig()}
		_, err := client.X509ValidateCertificate(ValidateCertificateRequest{})
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("error = %v, want inconsistent native length", err)
		}
	})

	t.Run("last error string", func(t *testing.T) {
		ctx := &fakeNativeContext{
			lastErrorStringFunc: func(int) (kalkancrypt.BufferResult, error) {
				return kalkancrypt.BufferResult{Code: uint64(ErrorOK), OutLen: -1}, nil
			},
		}
		client := &Client{ctx: ctx, config: defaultConfig()}
		code, message := client.GetLastErrorString()
		if code != ErrorMemory || !strings.Contains(message, "negative") {
			t.Fatalf("GetLastErrorString = (%s, %q), want ErrorMemory and negative length", code.Hex(), message)
		}
	})

	t.Run("last error string length mismatch", func(t *testing.T) {
		ctx := &fakeNativeContext{
			lastErrorStringFunc: func(int) (kalkancrypt.BufferResult, error) {
				return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("x"), OutLen: 2}, nil
			},
		}
		client := &Client{ctx: ctx, config: defaultConfig()}
		code, message := client.GetLastErrorString()
		if code != ErrorMemory || !strings.Contains(message, "does not match") {
			t.Fatalf("GetLastErrorString = (%s, %q), want ErrorMemory and inconsistent length", code.Hex(), message)
		}
	})
}

func TestValidateCertificateGrowsOnlyRequiredOutputBuffer(t *testing.T) {
	const (
		infoCapacity = 17
		ocspCapacity = 19
	)

	var calls []kalkancrypt.ValidateCertificateCall
	ctx := &fakeNativeContext{
		validateCertificateFunc: func(call kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
			calls = append(calls, call)
			if len(calls) == 1 {
				return kalkancrypt.ValidateResult{
					Code:    uint64(ErrorBufferTooSmall),
					InfoLen: call.InfoCapacity + 7,
				}, nil
			}

			return kalkancrypt.ValidateResult{Code: uint64(ErrorOK), Info: []byte("ok"), InfoLen: 2}, nil
		},
	}
	client := &Client{ctx: ctx, config: defaultConfig()}

	_, err := client.X509ValidateCertificate(ValidateCertificateRequest{
		OutputCapacity: infoCapacity,
		OCSPCapacity:   ocspCapacity,
	})
	if err != nil {
		t.Fatalf("X509ValidateCertificate failed: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	if calls[1].InfoCapacity != infoCapacity+7 || calls[1].OCSPCapacity != ocspCapacity {
		t.Fatalf("second capacities = info:%d ocsp:%d", calls[1].InfoCapacity, calls[1].OCSPCapacity)
	}
}

func TestMultiOutputMethodsGrowAllBuffersWithoutReportedLengths(t *testing.T) {
	t.Run("VerifyData", func(t *testing.T) {
		var calls []kalkancrypt.VerifyDataCall
		ctx := &fakeNativeContext{
			verifyDataFunc: func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
				calls = append(calls, call)
				if len(calls) == 1 {
					return kalkancrypt.VerifyResult{Code: uint64(ErrorBufferTooSmall)}, nil
				}

				return kalkancrypt.VerifyResult{Code: uint64(ErrorOK)}, nil
			},
		}
		client := &Client{ctx: ctx, config: defaultConfig()}

		_, err := client.VerifyData(VerifyDataRequest{
			Flags:              SignCMS,
			DataCapacity:       8,
			VerifyInfoCapacity: 9,
			CertCapacity:       10,
		})
		if err != nil {
			t.Fatalf("VerifyData failed: %v", err)
		}
		if len(calls) != 2 {
			t.Fatalf("calls = %d, want 2", len(calls))
		}
		if second := calls[1]; second.DataCapacity != 16 || second.InfoCapacity != 18 || second.CertCapacity != 20 {
			t.Fatalf("second capacities = data:%d info:%d cert:%d, want 16/18/20",
				second.DataCapacity, second.InfoCapacity, second.CertCapacity)
		}
	})

	t.Run("X509ValidateCertificate", func(t *testing.T) {
		var calls []kalkancrypt.ValidateCertificateCall
		ctx := &fakeNativeContext{
			validateCertificateFunc: func(call kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
				calls = append(calls, call)
				if len(calls) == 1 {
					return kalkancrypt.ValidateResult{Code: uint64(ErrorBufferTooSmall)}, nil
				}

				return kalkancrypt.ValidateResult{Code: uint64(ErrorOK)}, nil
			},
		}
		client := &Client{ctx: ctx, config: defaultConfig()}

		_, err := client.X509ValidateCertificate(ValidateCertificateRequest{
			OutputCapacity: 11,
			OCSPCapacity:   13,
		})
		if err != nil {
			t.Fatalf("X509ValidateCertificate failed: %v", err)
		}
		if len(calls) != 2 {
			t.Fatalf("calls = %d, want 2", len(calls))
		}
		if second := calls[1]; second.InfoCapacity != 22 || second.OCSPCapacity != 26 {
			t.Fatalf("second capacities = info:%d ocsp:%d, want 22/26", second.InfoCapacity, second.OCSPCapacity)
		}
	})
}

func bufferTooSmallOnce(capacities *[]int, capacity int) (kalkancrypt.BufferResult, error) {
	*capacities = append(*capacities, capacity)
	if len(*capacities) == 1 {
		return kalkancrypt.BufferResult{Code: uint64(ErrorBufferTooSmall), OutLen: capacity + 11}, nil
	}

	return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
}

func listBufferTooSmallOnce(capacities *[]int, capacity int) (kalkancrypt.ListResult, error) {
	*capacities = append(*capacities, capacity)
	if len(*capacities) == 1 {
		return kalkancrypt.ListResult{Code: uint64(ErrorBufferTooSmall)}, nil
	}

	return kalkancrypt.ListResult{Code: uint64(ErrorOK), Data: "ok", Count: 1}, nil
}

func TestBytesBeforeNULTerminator(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{name: "plain text", input: []byte("text"), want: "text"},
		{name: "terminal NUL", input: []byte{'t', 'e', 'x', 't', 0}, want: "text"},
		{name: "empty C string", input: []byte{0}, want: ""},
		{name: "NUL padding", input: []byte{'t', 'e', 'x', 't', 0, 0, 0}, want: "text"},
		{name: "unspecified suffix", input: []byte{'t', 'e', 0, 'x', 't'}, want: "te"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := bytesBeforeNULTerminator(test.input)
			if string(got) != test.want {
				t.Fatalf("bytesBeforeNULTerminator(%v) = %q, want %q", test.input, got, test.want)
			}
			if len(got) != cap(got) {
				t.Fatalf("result len/cap = %d/%d, want equal", len(got), cap(got))
			}
		})
	}
}

func TestTextOutputsUseCStringPrefix(t *testing.T) {
	nativeOutput := []byte{'o', 'k', 0, 'x'}

	tests := []struct {
		name        string
		install     func(*fakeNativeContext)
		call        func(*Client) ([]byte, error)
		returnsView bool
	}{
		{
			name: "SignXML",
			install: func(ctx *fakeNativeContext) {
				ctx.signXMLFunc = func(kalkancrypt.SignXMLCall) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				return client.SignXML(SignXMLRequest{XML: []byte("<root/>")})
			},
			returnsView: true,
		},
		{
			name: "SignWSSE",
			install: func(ctx *fakeNativeContext) {
				ctx.signWSSEFunc = func(kalkancrypt.SignWSSECall) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				return client.SignWSSE(SignWSSERequest{XML: []byte("<root/>")})
			},
			returnsView: true,
		},
		{
			name: "VerifyXML",
			install: func(ctx *fakeNativeContext) {
				ctx.verifyXMLFunc = func(kalkancrypt.VerifyXMLCall) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				value, err := client.VerifyXML("", 0, []byte("<root/>"))
				return []byte(value), err
			},
		},
		{
			name: "GetSigAlgFromXML",
			install: func(ctx *fakeNativeContext) {
				ctx.getSigAlgFromXMLFunc = func([]byte, int) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				value, err := client.GetSigAlgFromXML([]byte("<root/>"))
				return []byte(value), err
			},
		},
		{
			name: "ZipConVerify",
			install: func(ctx *fakeNativeContext) {
				ctx.zipConVerifyFunc = func(string, int, int) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				value, err := client.ZipConVerify("signed.zip", 0)
				return []byte(value), err
			},
		},
		{
			name: "X509CertificateGetInfo",
			install: func(ctx *fakeNativeContext) {
				ctx.x509InfoFunc = func([]byte, int, int) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				return client.X509CertificateGetInfo([]byte("cert"), CertPropSubjectCommonName)
			},
			returnsView: true,
		},
		{
			name: "VerifyData.VerifyInfo",
			install: func(ctx *fakeNativeContext) {
				ctx.verifyDataFunc = func(kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
					return kalkancrypt.VerifyResult{
						Code:    uint64(ErrorOK),
						Info:    nativeOutput,
						InfoLen: len(nativeOutput),
					}, nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				value, err := client.VerifyData(VerifyDataRequest{Flags: SignCMS})
				return []byte(value.VerifyInfo), err
			},
		},
		{
			name: "X509ValidateCertificate.Info",
			install: func(ctx *fakeNativeContext) {
				ctx.validateCertificateFunc = func(kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
					return kalkancrypt.ValidateResult{
						Code:    uint64(ErrorOK),
						Info:    nativeOutput,
						InfoLen: len(nativeOutput),
					}, nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				value, err := client.X509ValidateCertificate(ValidateCertificateRequest{})
				return []byte(value.Info), err
			},
		},
		{
			name: "GetLastErrorString",
			install: func(ctx *fakeNativeContext) {
				ctx.lastErrorStringFunc = func(int) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				_, value := client.GetLastErrorString()
				return []byte(value), nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &fakeNativeContext{}
			test.install(ctx)
			client := &Client{ctx: ctx, config: defaultConfig()}

			got, err := test.call(client)
			if err != nil {
				t.Fatalf("call returned error: %v", err)
			}
			if string(got) != "ok" {
				t.Fatalf("output = %q, want C-string prefix", got)
			}
			if test.returnsView {
				if &got[0] != &nativeOutput[0] {
					t.Fatal("output was copied")
				}
				if len(got) != cap(got) {
					t.Fatalf("output len/cap = %d/%d, want equal", len(got), cap(got))
				}
			}
		})
	}
}

func TestBinaryOutputsPreserveReportedBytes(t *testing.T) {
	nativeOutput := []byte{1, 0, 2, 0}

	tests := []struct {
		name    string
		install func(*fakeNativeContext)
		call    func(*Client) ([]byte, error)
	}{
		{
			name: "HashData",
			install: func(ctx *fakeNativeContext) {
				ctx.hashDataFunc = func(kalkancrypt.HashDataCall) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				return client.HashData(SHA256, 0, []byte("data"))
			},
		},
		{
			name: "SignHash",
			install: func(ctx *fakeNativeContext) {
				ctx.signHashFunc = func(kalkancrypt.SignHashCall) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				return client.SignHash("", 0, []byte("hash"))
			},
		},
		{
			name: "SignData",
			install: func(ctx *fakeNativeContext) {
				ctx.signDataFunc = func(kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				return client.SignData(SignDataRequest{Flags: SignCMS, Data: []byte("data")})
			},
		},
		{
			name: "GetCertFromXML",
			install: func(ctx *fakeNativeContext) {
				ctx.getCertFromXMLFunc = func([]byte, int, int) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				return client.GetCertFromXML([]byte("<root/>"), 0)
			},
		},
		{
			name: "GetCertFromCMS",
			install: func(ctx *fakeNativeContext) {
				ctx.getCertFromCMSFunc = func(kalkancrypt.GetCertFromCMSCall) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				return client.GetCertFromCMS([]byte("cms"), 0, InDER)
			},
		},
		{
			name: "GetCertFromZipFile",
			install: func(ctx *fakeNativeContext) {
				ctx.getCertFromZipFileFunc = func(kalkancrypt.GetCertFromZipFileCall) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				return client.GetCertFromZipFile("signed.zip", 0, 0)
			},
		},
		{
			name: "X509ExportCertificateFromStore",
			install: func(ctx *fakeNativeContext) {
				ctx.x509ExportFunc = func(string, int, int) (kalkancrypt.BufferResult, error) {
					return okBufferResult(nativeOutput), nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				return client.X509ExportCertificateFromStore("", CertDER)
			},
		},
		{
			name: "VerifyData.Data",
			install: func(ctx *fakeNativeContext) {
				ctx.verifyDataFunc = func(kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
					return kalkancrypt.VerifyResult{
						Code:    uint64(ErrorOK),
						Data:    nativeOutput,
						DataLen: len(nativeOutput),
					}, nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				value, err := client.VerifyData(VerifyDataRequest{Flags: SignCMS})
				return value.Data, err
			},
		},
		{
			name: "VerifyData.Cert",
			install: func(ctx *fakeNativeContext) {
				ctx.verifyDataFunc = func(kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
					return kalkancrypt.VerifyResult{
						Code:    uint64(ErrorOK),
						Cert:    nativeOutput,
						CertLen: len(nativeOutput),
					}, nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				value, err := client.VerifyData(VerifyDataRequest{Flags: SignCMS})
				return value.Cert, err
			},
		},
		{
			name: "X509ValidateCertificate.OCSPResponse",
			install: func(ctx *fakeNativeContext) {
				ctx.validateCertificateFunc = func(kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
					return kalkancrypt.ValidateResult{
						Code:    uint64(ErrorOK),
						OCSP:    nativeOutput,
						OCSPLen: len(nativeOutput),
					}, nil
				}
			},
			call: func(client *Client) ([]byte, error) {
				value, err := client.X509ValidateCertificate(ValidateCertificateRequest{})
				return value.OCSPResponse, err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &fakeNativeContext{}
			test.install(ctx)
			client := &Client{ctx: ctx, config: defaultConfig()}

			got, err := test.call(client)
			if err != nil {
				t.Fatalf("call returned error: %v", err)
			}
			if !bytes.Equal(got, nativeOutput) {
				t.Fatalf("output = %v, want %v", got, nativeOutput)
			}
			if &got[0] != &nativeOutput[0] {
				t.Fatal("output was copied")
			}
			if len(got) != cap(got) {
				t.Fatalf("output len/cap = %d/%d, want equal", len(got), cap(got))
			}
		})
	}
}

func okBufferResult(data []byte) kalkancrypt.BufferResult {
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: data, OutLen: len(data)}
}
