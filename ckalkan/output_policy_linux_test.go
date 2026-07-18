//go:build linux

package ckalkan

import (
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestVerifyDataRetriesSaturatedAttachedData(t *testing.T) {
	const (
		initialDataCapacity = 8
		initialInfoCapacity = 9
		initialCertCapacity = 10
	)

	tests := []struct {
		name          string
		signature     []byte
		secondDataCap int
	}{
		{name: "uses CMS size hint", signature: repeatedBytes('s', 32), secondDataCap: 32},
		{name: "doubles without a hint", secondDataCap: 16},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &fakeNativeContext{}
			var calls []kalkancrypt.VerifyDataCall
			ctx.verifyDataFunc = func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
				calls = append(calls, call)
				if len(calls) == 1 {
					return kalkancrypt.VerifyResult{
						Code:    uint64(ErrorOK),
						Data:    repeatedBytes('x', call.DataCapacity),
						DataLen: call.DataCapacity,
						Info:    []byte("info"),
						InfoLen: len("info"),
						Cert:    []byte("cert"),
						CertLen: len("cert"),
					}, nil
				}

				return kalkancrypt.VerifyResult{
					Code:    uint64(ErrorOK),
					Data:    []byte("complete-data"),
					DataLen: len("complete-data"),
					Info:    []byte("info"),
					InfoLen: len("info"),
					Cert:    []byte("cert"),
					CertLen: len("cert"),
				}, nil
			}

			cli := &Client{ctx: ctx, config: defaultConfig()}
			got, err := cli.VerifyData(VerifyDataRequest{
				Flags:              SignCMS,
				Signature:          test.signature,
				DataCapacity:       initialDataCapacity,
				VerifyInfoCapacity: initialInfoCapacity,
				CertCapacity:       initialCertCapacity,
			})
			if err != nil {
				t.Fatalf("VerifyData failed: %v", err)
			}
			if string(got.Data) != "complete-data" || got.VerifyInfo != "info" || string(got.Cert) != "cert" {
				t.Fatalf("VerifyData returned %+v", got)
			}
			if len(calls) != 2 {
				t.Fatalf("calls = %d, want 2", len(calls))
			}

			first, second := calls[0], calls[1]
			if first.DataCapacity != initialDataCapacity ||
				first.InfoCapacity != initialInfoCapacity ||
				first.CertCapacity != initialCertCapacity {
				t.Fatalf("first capacities = data:%d info:%d cert:%d", first.DataCapacity, first.InfoCapacity, first.CertCapacity)
			}
			if second.DataCapacity != test.secondDataCap ||
				second.InfoCapacity != initialInfoCapacity ||
				second.CertCapacity != initialCertCapacity {
				t.Fatalf("second capacities = data:%d info:%d cert:%d", second.DataCapacity, second.InfoCapacity, second.CertCapacity)
			}
		})
	}
}

func TestVerifyDataGrowsOnlyUsedBuffers(t *testing.T) {
	const (
		initialInfoCapacity = 9
		initialCertCapacity = 10
	)

	var calls []kalkancrypt.VerifyDataCall
	ctx := &fakeNativeContext{
		verifyDataFunc: func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
			calls = append(calls, call)
			if len(calls) == 1 {
				return kalkancrypt.VerifyResult{
					Code:    uint64(ErrorBufferTooSmall),
					DataLen: call.DataCapacity,
					InfoLen: call.InfoCapacity + 7,
				}, nil
			}

			return kalkancrypt.VerifyResult{
				Code:    uint64(ErrorOK),
				Data:    make([]byte, call.DataCapacity),
				DataLen: call.DataCapacity,
				Info:    []byte("info"),
				InfoLen: len("info"),
			}, nil
		},
	}

	client := &Client{ctx: ctx, config: defaultConfig()}
	got, err := client.VerifyData(VerifyDataRequest{
		Flags:              SignCMS | DetachedData,
		DataCapacity:       128,
		VerifyInfoCapacity: initialInfoCapacity,
		CertCapacity:       initialCertCapacity,
	})
	if err != nil {
		t.Fatalf("VerifyData failed: %v", err)
	}
	if got.Data != nil {
		t.Fatalf("Data = %x, want nil", got.Data)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}

	second := calls[1]
	if second.DataCapacity != 1 ||
		second.InfoCapacity != initialInfoCapacity+7 ||
		second.CertCapacity != initialCertCapacity {
		t.Fatalf("second capacities = data:%d info:%d cert:%d", second.DataCapacity, second.InfoCapacity, second.CertCapacity)
	}
}

func TestVerifyDataSaturatedAttachedDataHonorsHardLimit(t *testing.T) {
	ctx := &fakeNativeContext{}
	ctx.verifyDataFunc = func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
		return kalkancrypt.VerifyResult{
			Code:    uint64(ErrorOK),
			Data:    repeatedBytes('x', call.DataCapacity),
			DataLen: call.DataCapacity,
		}, nil
	}

	cli := &Client{ctx: ctx, config: config{
		bufferSize:    conservativeOutputBufferSize,
		maxBufferSize: conservativeOutputBufferSize,
	}}
	_, err := cli.VerifyData(VerifyDataRequest{
		Flags:     SignCMS,
		Signature: repeatedBytes('s', conservativeOutputBufferSize*2),
	})
	if err == nil {
		t.Fatal("VerifyData unexpectedly succeeded")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
}

func TestZipConVerifyHonorsHardLimitBelowNativeSafetyBuffer(t *testing.T) {
	const hardLimit = initialZIPVerifyBuffer - 1

	ctx := &fakeNativeContext{
		zipConVerifyFunc: func(string, int, int) (kalkancrypt.BufferResult, error) {
			t.Error("ZipConVerify reached native with an unsafe configured capacity")
			return kalkancrypt.BufferResult{}, nil
		},
	}
	client := &Client{ctx: ctx, config: config{maxBufferSize: hardLimit}}

	_, err := client.ZipConVerify("signed.zip", 0)
	if err == nil {
		t.Fatal("ZipConVerify unexpectedly exceeded the hard limit")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
}
