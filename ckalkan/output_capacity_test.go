package ckalkan

import (
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestCallBufferWithCapacityUsesOperationInitialBelowConservativeSize(t *testing.T) {
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
	if want := []int{128}; !equalInts(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
	}
}

func TestOperationDefaultInitialOutputCapacities(t *testing.T) {
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
				ctx.hashDataFunc = func(_ string, _ int, _ []byte, got int) (kalkancrypt.BufferResult, error) {
					*capacity = got
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("hash"), OutLen: 4}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.HashData(SHA256, 0, []byte("data"))
				return err
			},
		},
		{
			name: "SignData",
			want: wantSignatureOutput,
			install: func(ctx *fakeNativeContext, capacity *int) {
				ctx.signDataFunc = func(_ string, _ int, _, _ []byte, got int) (kalkancrypt.BufferResult, error) {
					*capacity = got
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("sig"), OutLen: 3}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.SignData("alias", 0, []byte("data"), nil)
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
				ctx.getCertFromCMSFunc = func(_ []byte, _, _, got int) (kalkancrypt.BufferResult, error) {
					*capacity = got
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("cert"), OutLen: 4}, nil
				}
			},
			call: func(cli *Client) error {
				_, err := cli.GetCertFromCMS([]byte("cms"), 0, 0)
				return err
			},
		},
		{
			name: "ZipConVerify",
			want: wantInfoOutput,
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

func TestConfiguredBufferSizeOverridesOperationInitialCapacity(t *testing.T) {
	var firstCapacity int
	ctx := &fakeNativeContext{}
	ctx.hashDataFunc = func(_ string, _ int, _ []byte, capacity int) (kalkancrypt.BufferResult, error) {
		firstCapacity = capacity
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

func TestSignatureOperationsUseConservativeInitialOutputCapacity(t *testing.T) {
	largeInput := bytesOf('x', conservativeOutputBufferSize*3)

	tests := []struct {
		name string
		call func(*Client, *fakeNativeContext) ([]byte, error)
	}{
		{
			name: "SignData",
			call: func(cli *Client, ctx *fakeNativeContext) ([]byte, error) {
				return cli.SignData("alias", SignCMS, largeInput, largeInput)
			},
		},
		{
			name: "SignXML",
			call: func(cli *Client, ctx *fakeNativeContext) ([]byte, error) {
				return cli.SignXML(SignXMLRequest{Alias: "alias", XML: largeInput})
			},
		},
		{
			name: "SignWSSE",
			call: func(cli *Client, ctx *fakeNativeContext) ([]byte, error) {
				return cli.SignWSSE(SignWSSERequest{Alias: "alias", XML: largeInput})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var firstCapacity int
			ctx := &fakeNativeContext{}
			ctx.hashDataFunc = func(_ string, _ int, _ []byte, capacity int) (kalkancrypt.BufferResult, error) {
				firstCapacity = capacity
				return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
			}
			ctx.signDataFunc = func(_ string, _ int, _, _ []byte, capacity int) (kalkancrypt.BufferResult, error) {
				firstCapacity = capacity
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

			cli := &Client{
				ctx: ctx,
				config: config{
					maxBufferSize: conservativeOutputBufferSize,
				},
			}

			if _, err := test.call(cli, ctx); err != nil {
				t.Fatalf("%s returned error: %v", test.name, err)
			}
			if firstCapacity != conservativeOutputBufferSize {
				t.Fatalf("%s first capacity = %d, want %d", test.name, firstCapacity, conservativeOutputBufferSize)
			}
		})
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
		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("native message\x00ignored"), OutLen: len("native message\x00ignored")}, nil
	}

	cli := &Client{ctx: ctx, config: defaultConfig()}
	code, message := cli.GetLastErrorString()
	if code != ErrorOK || message != "native message" {
		t.Fatalf("GetLastErrorString = (%s, %q), want (%s, %q)", code.Hex(), message, ErrorOK.Hex(), "native message")
	}
	if want := []int{4 << 10, (4 << 10) + 7}; !equalInts(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
	}
}

func TestLastErrorStringRetriesWhenOKReportsOversizedOutput(t *testing.T) {
	ctx := &fakeNativeContext{}
	var capacities []int
	ctx.lastErrorStringFunc = func(capacity int) (kalkancrypt.BufferResult, error) {
		capacities = append(capacities, capacity)
		if len(capacities) == 1 {
			return kalkancrypt.BufferResult{
				Code:   uint64(ErrorOK),
				Data:   bytesOf('x', capacity),
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
	if want := []int{conservativeOutputBufferSize, conservativeOutputBufferSize + 7}; !equalInts(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
	}
}
