package ckalkan

import (
	"encoding/base64"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestCallBufferUsesSmallInitialSize(t *testing.T) {
	var capacities []int
	cli := &Client{config: defaultConfig()}

	got, err := cli.callBufferWithCapacityLocked(128, func(capacity int) (kalkancrypt.BufferResult, error) {
		capacities = append(capacities, capacity)
		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
	})
	if err != nil {
		t.Fatalf("callBufferWithCapacityLocked failed: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("output = %q, want ok", got)
	}
	if want := []int{128}; !slices.Equal(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
	}
}

func TestSingleOutputMethodsUseOperationSpecificInitialCapacity(t *testing.T) {
	const (
		wantHashOutput      = 128
		wantInfoOutput      = 4 << 10
		wantCertOutput      = 8 << 10
		wantSignatureOutput = 64 << 10
	)

	tests := []struct {
		name    string
		want    int
		install func(*fakeNativeContext, *int)
		call    func(*Client) error
	}{
		{
			name: "HashData",
			want: wantHashOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.hashDataFunc = func(call kalkancrypt.HashDataCall) (kalkancrypt.BufferResult, error) {
					*capacity = call.Capacity
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("hash"), OutLen: 4}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.HashData(SHA256, 0, []byte("data"))
				return err
			},
		},
		{
			name: "SignHash",
			want: wantSignatureOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.signHashFunc = func(call kalkancrypt.SignHashCall) (kalkancrypt.BufferResult, error) {
					*capacity = call.Capacity
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("sig"), OutLen: 3}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.SignHash("alias", 0, []byte("hash"))
				return err
			},
		},
		{
			name: "SignData",
			want: wantSignatureOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.signDataFunc = func(call kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error) {
					*capacity = call.Capacity
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("sig"), OutLen: 3}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.SignData(SignDataRequest{Alias: "alias", Data: []byte("data")})
				return err
			},
		},
		{
			name: "SignXML",
			want: wantSignatureOutput + len("<doc/>"),
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.signXMLFunc = func(call kalkancrypt.SignXMLCall) (kalkancrypt.BufferResult, error) {
					*capacity = call.Capacity
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("<signed/>"), OutLen: len("<signed/>")}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.SignXML(SignXMLRequest{XML: []byte("<doc/>"), Flags: XMLInclC14N})
				return err
			},
		},
		{
			name: "SignWSSE",
			want: wantSignatureOutput + len("<doc/>"),
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.signWSSEFunc = func(call kalkancrypt.SignWSSECall) (kalkancrypt.BufferResult, error) {
					*capacity = call.Capacity
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("<signed/>"), OutLen: len("<signed/>")}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.SignWSSE(SignWSSERequest{XML: []byte("<doc/>"), Flags: XMLInclC14N})
				return err
			},
		},
		{
			name: "VerifyXML",
			want: wantInfoOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.verifyXMLFunc = func(call kalkancrypt.VerifyXMLCall) (kalkancrypt.BufferResult, error) {
					*capacity = call.Capacity
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("info"), OutLen: 4}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.VerifyXML("", 0, []byte("<doc/>"))
				return err
			},
		},
		{
			name: "X509CertificateGetInfo",
			want: wantInfoOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.x509InfoFunc = func(_ []byte, _, got int) (kalkancrypt.BufferResult, error) {
					*capacity = got
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("info"), OutLen: 4}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.X509CertificateGetInfo([]byte("cert"), CertPropSubjectCommonName)
				return err
			},
		},
		{
			name: "X509ExportCertificateFromStore",
			want: wantCertOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.x509ExportFunc = func(_ string, _, got int) (kalkancrypt.BufferResult, error) {
					*capacity = got
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("cert"), OutLen: 4}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.X509ExportCertificateFromStore("alias", CertPEM)
				return err
			},
		},
		{
			name: "GetCertFromXML",
			want: wantCertOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.getCertFromXMLFunc = func(_ []byte, _, got int) (kalkancrypt.BufferResult, error) {
					*capacity = got
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("cert"), OutLen: 4}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.GetCertFromXML([]byte("<doc/>"), 0)
				return err
			},
		},
		{
			name: "GetSigAlgFromXML",
			want: wantInfoOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.getSigAlgFromXMLFunc = func(_ []byte, got int) (kalkancrypt.BufferResult, error) {
					*capacity = got
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("alg"), OutLen: 3}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.GetSigAlgFromXML([]byte("<doc/>"))
				return err
			},
		},
		{
			name: "GetCertFromCMS",
			want: wantCertOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.getCertFromCMSFunc = func(call kalkancrypt.GetCertFromCMSCall) (kalkancrypt.BufferResult, error) {
					*capacity = call.Capacity
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("cert"), OutLen: 4}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.GetCertFromCMS([]byte("cms"), 0, 0)
				return err
			},
		},
		{
			name: "GetCertFromZipFile",
			want: wantCertOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.getCertFromZipFileFunc = func(call kalkancrypt.GetCertFromZipFileCall) (kalkancrypt.BufferResult, error) {
					*capacity = call.Capacity
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("cert"), OutLen: 4}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.GetCertFromZipFile("signed.zip", 0, 0)
				return err
			},
		},
		{
			name: "ZipConVerify",
			want: initialZIPVerifyBuffer,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.zipConVerifyFunc = func(_ string, _, got int) (kalkancrypt.BufferResult, error) {
					*capacity = got
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.ZipConVerify("signed.zip", 0)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			firstCapacity := -1
			ctx := &fakeNativeContext{}
			test.install(ctx, &firstCapacity)

			cli := &Client{ctx: ctx, config: defaultConfig()}
			if err := test.call(cli); err != nil {
				t.Fatalf("%s returned error: %v", test.name, err)
			}
			if firstCapacity != test.want {
				t.Fatalf("%s first capacity = %d, want %d", test.name, firstCapacity, test.want)
			}
		})
	}
}

func TestConfiguredBufferSizeIsClampedToConservativeMinimum(t *testing.T) {
	var firstCapacity int
	ctx := &fakeNativeContext{}
	ctx.hashDataFunc = func(call kalkancrypt.HashDataCall) (kalkancrypt.BufferResult, error) {
		firstCapacity = call.Capacity
		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("hash"), OutLen: 4}, nil
	}

	cfg := defaultConfig()
	WithBufferSize(128)(&cfg)
	cli := &Client{ctx: ctx, config: cfg}

	if _, err := cli.HashData(SHA256, 0, []byte("data")); err != nil {
		t.Fatalf("HashData failed: %v", err)
	}
	if firstCapacity != conservativeOutputBufferSize {
		t.Fatalf("HashData first capacity = %d, want configured conservative output size %d", firstCapacity, conservativeOutputBufferSize)
	}
}

func BenchmarkCallBufferSmallInitialOutput(b *testing.B) {
	cli := &Client{config: defaultConfig()}
	output := []byte("small")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		got, err := cli.callBufferWithCapacityLocked(initialHashOutputBuffer, func(capacity int) (kalkancrypt.BufferResult, error) {
			if capacity != initialHashOutputBuffer {
				b.Fatalf("capacity = %d, want %d", capacity, initialHashOutputBuffer)
			}
			return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: output, OutLen: len(output)}, nil
		})
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != len(output) {
			b.Fatalf("output length = %d, want %d", len(got), len(output))
		}
	}
}

func TestAttachedSignatureMethodsEstimateOutputFromInputLength(t *testing.T) {
	largeInput := repeatedBytes('x', conservativeOutputBufferSize*3)

	tests := []struct {
		name string
		call func(*Client) ([]byte, error)
	}{
		{
			name: "SignData",
			call: func(cli *Client) ([]byte, error) {
				return cli.SignData(SignDataRequest{
					Alias: "alias",
					Flags: SignCMS,
					Data:  largeInput,
				})
			},
		},
		{
			name: "SignXML",
			call: func(cli *Client) ([]byte, error) {
				return cli.SignXML(SignXMLRequest{Alias: "alias", XML: largeInput})
			},
		},
		{
			name: "SignWSSE",
			call: func(cli *Client) ([]byte, error) {
				return cli.SignWSSE(SignWSSERequest{Alias: "alias", XML: largeInput})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var firstCapacity int
			ctx := &fakeNativeContext{}
			ctx.signDataFunc = func(call kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error) {
				firstCapacity = call.Capacity
				return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
			}
			ctx.signXMLFunc = func(call kalkancrypt.SignXMLCall) (kalkancrypt.BufferResult, error) {
				firstCapacity = call.Capacity
				return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
			}
			ctx.signWSSEFunc = func(call kalkancrypt.SignWSSECall) (kalkancrypt.BufferResult, error) {
				firstCapacity = call.Capacity
				return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
			}

			cli := &Client{ctx: ctx, config: defaultConfig()}

			if _, err := test.call(cli); err != nil {
				t.Fatalf("%s returned error: %v", test.name, err)
			}
			want := len(largeInput) + signatureOutputOverhead
			if firstCapacity != want {
				t.Fatalf("%s first capacity = %d, want %d", test.name, firstCapacity, want)
			}
		})
	}
}

func TestBase64OutputEstimateDetectsNativeLimitWithoutIntegerOverflow(t *testing.T) {
	want := int64(maxNativeOutputBufferSize) + 1
	for _, test := range []struct {
		name      string
		estimated int64
	}{
		{name: "native-sized Base64 output", estimated: base64EncodedEstimate(maxNativeOutputBufferSize)},
		{name: "MaxInt64 Base64 output", estimated: base64EncodedEstimate(math.MaxInt64)},
		{name: "MaxInt64 Base64 input", estimated: decodedBase64UpperBound(math.MaxInt64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.estimated != want {
				t.Fatalf("estimate = %d, want saturated value %d", test.estimated, want)
			}
		})
	}

	_, err := checkedOutputEstimate("test", want)
	if err == nil {
		t.Fatal("checkedOutputEstimate accepted an output larger than the native limit")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
}

func TestSignDataEstimatesAttachedFileAndOutputEncoding(t *testing.T) {
	const fileSize = 100 << 20

	path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, fileSize); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		flags Flag
		want  int
	}{
		{
			name:  "DER",
			flags: SignCMS | InFile | OutDER,
			want:  fileSize + signatureOutputOverhead,
		},
		{
			name:  "Base64",
			flags: SignCMS | InFile | OutBase64,
			want:  base64.StdEncoding.EncodedLen(fileSize + signatureOutputOverhead),
		},
		{
			name:  "PEM",
			flags: SignCMS | InFile | OutPEM,
			want: func() int {
				encoded := base64.StdEncoding.EncodedLen(fileSize + signatureOutputOverhead)

				return encoded + ((encoded+pemLineWidth-1)/pemLineWidth)*2 + pemEnvelopeOverhead
			}(),
		},
		{
			name:  "detached ignores payload size",
			flags: SignCMS | InFile | OutDER | DetachedData,
			want:  signatureOutputOverhead,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var capacity int
			ctx := &fakeNativeContext{
				signDataFunc: func(call kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error) {
					capacity = call.Capacity

					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
				},
			}
			cli := &Client{ctx: ctx, config: defaultConfig()}

			if _, err := cli.SignData(SignDataRequest{Flags: test.flags, Data: []byte(path)}); err != nil {
				t.Fatalf("SignData failed: %v", err)
			}
			if capacity != test.want {
				t.Fatalf("initial capacity = %d, want %d", capacity, test.want)
			}
		})
	}
}

func TestSignDataFileEstimateKeepsExistingSignatureInMemory(t *testing.T) {
	dataPath := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(dataPath, []byte{'x'}, 0o600); err != nil {
		t.Fatal(err)
	}

	// The bytes intentionally spell the path of a much larger real file. With
	// KC_IN_FILE only Data is a path; Signature remains an in-memory secondary
	// input and its byte length must be used for the estimate.
	signaturePath := filepath.Join(t.TempDir(), "existing.cms")
	if err := os.WriteFile(signaturePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(signaturePath, 8<<20); err != nil {
		t.Fatal(err)
	}

	var capacity int
	ctx := &fakeNativeContext{
		signDataFunc: func(call kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error) {
			capacity = call.Capacity

			return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
		},
	}
	cli := &Client{ctx: ctx, config: defaultConfig()}

	_, err := cli.SignData(SignDataRequest{
		Flags:     SignCMS | InFile,
		Data:      []byte(dataPath),
		Signature: []byte(signaturePath),
	})
	if err != nil {
		t.Fatalf("SignData failed: %v", err)
	}

	want := len(signaturePath) + signatureOutputOverhead
	if capacity != want {
		t.Fatalf("initial capacity = %d, want in-memory signature estimate %d", capacity, want)
	}
}

func TestSignDataHonorsHardLimitBelowEstimatedOutput(t *testing.T) {
	const hardLimit = 1024

	var capacities []int
	ctx := &fakeNativeContext{
		signDataFunc: func(call kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error) {
			capacities = append(capacities, call.Capacity)

			return kalkancrypt.BufferResult{
				Code:   uint64(ErrorBufferTooSmall),
				OutLen: hardLimit + 1,
			}, nil
		},
	}
	cfg := defaultConfig()
	WithMaxBufferSize(hardLimit)(&cfg)
	cli := &Client{ctx: ctx, config: cfg}

	_, err := cli.SignData(SignDataRequest{
		Flags: SignCMS,
		Data:  repeatedBytes('x', conservativeOutputBufferSize*2),
	})
	if err == nil {
		t.Fatal("SignData unexpectedly exceeded the hard limit")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
	if want := []int{hardLimit}; !slices.Equal(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
	}
}

func TestSignDataExplicitCapacityOverridesEstimate(t *testing.T) {
	const requested = 123

	var capacity int
	ctx := &fakeNativeContext{
		signDataFunc: func(call kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error) {
			capacity = call.Capacity

			return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
		},
	}
	cli := &Client{ctx: ctx, config: defaultConfig()}

	if _, err := cli.SignData(SignDataRequest{
		Flags:          SignCMS,
		Data:           repeatedBytes('x', conservativeOutputBufferSize*2),
		OutputCapacity: requested,
	}); err != nil {
		t.Fatalf("SignData failed: %v", err)
	}
	if capacity != requested {
		t.Fatalf("initial capacity = %d, want explicit %d", capacity, requested)
	}
}

func TestLastErrorStringRetriesAfterBufferTooSmall(t *testing.T) {
	ctx := &fakeNativeContext{}
	var capacities []int
	ctx.lastErrorStringFunc = func(capacity int) (kalkancrypt.BufferResult, error) {
		capacities = append(capacities, capacity)
		if len(capacities) == 1 {
			return kalkancrypt.BufferResult{Code: uint64(ErrorBufferTooSmall), OutLen: (4 << 10) + 7}, nil
		}
		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("native message\x00"), OutLen: len("native message\x00")}, nil
	}

	cli := &Client{ctx: ctx, config: defaultConfig()}
	code, message := cli.GetLastErrorString()
	if code != ErrorOK || message != "native message" {
		t.Fatalf("GetLastErrorString = (%s, %q), want (%s, %q)", code.Hex(), message, ErrorOK.Hex(), "native message")
	}
	if want := []int{4 << 10, (4 << 10) + 7}; !slices.Equal(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
	}
}

func TestLastErrorStringRetriesOversizedOutput(t *testing.T) {
	ctx := &fakeNativeContext{}
	var capacities []int
	ctx.lastErrorStringFunc = func(capacity int) (kalkancrypt.BufferResult, error) {
		capacities = append(capacities, capacity)
		if len(capacities) == 1 {
			return kalkancrypt.BufferResult{
				Code:   uint64(ErrorOK),
				Data:   repeatedBytes('x', capacity),
				OutLen: capacity + 7,
			}, nil
		}
		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("native message"), OutLen: len("native message")}, nil
	}

	cli := &Client{ctx: ctx, config: config{bufferSize: conservativeOutputBufferSize, maxBufferSize: conservativeOutputBufferSize * 2}}
	code, message := cli.GetLastErrorString()
	if code != ErrorOK || message != "native message" {
		t.Fatalf("GetLastErrorString = (%s, %q), want (%s, %q)", code.Hex(), message, ErrorOK.Hex(), "native message")
	}
	if want := []int{conservativeOutputBufferSize, conservativeOutputBufferSize + 7}; !slices.Equal(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
	}
}

func TestLastErrorStringReportsExplicitHardLimit(t *testing.T) {
	const hardLimit = 1024

	ctx := &fakeNativeContext{
		lastErrorStringFunc: func(capacity int) (kalkancrypt.BufferResult, error) {
			return kalkancrypt.BufferResult{
				Code:   uint64(ErrorBufferTooSmall),
				Data:   repeatedBytes('x', capacity),
				OutLen: capacity + 1,
			}, nil
		},
	}
	cli := &Client{ctx: ctx, config: config{maxBufferSize: hardLimit}}

	code, message := cli.GetLastErrorString()
	if code != ErrorBufferTooSmall {
		t.Fatalf("code = %s, want %s", code.Hex(), ErrorBufferTooSmall.Hex())
	}
	if !strings.Contains(message, "hard limit 1024") {
		t.Fatalf("message = %q, want explicit hard-limit error", message)
	}
}
