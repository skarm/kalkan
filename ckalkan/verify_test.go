package ckalkan

import (
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestVerifyDataGrowsAllReportedOutputsAfterBufferTooSmall(t *testing.T) {
	const (
		wantDataOutput = 64 << 10
		wantInfoOutput = 4 << 10
		wantCertOutput = 8 << 10
	)

	ctx := &fakeNativeContext{}
	var calls []kalkancrypt.VerifyDataCall
	ctx.verifyDataFunc = func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
		calls = append(calls, call)
		if len(calls) == 1 {
			return kalkancrypt.VerifyResult{
				Code:    uint64(ErrorBufferTooSmall),
				DataLen: wantDataOutput + 1,
				InfoLen: wantInfoOutput + 2,
				CertLen: wantCertOutput + 3,
			}, nil
		}

		return kalkancrypt.VerifyResult{
			Code:    uint64(ErrorOK),
			Data:    []byte("data"),
			DataLen: len("data"),
			Info:    []byte("info\x00"),
			InfoLen: len("info\x00"),
			Cert:    []byte("cert"),
			CertLen: len("cert"),
		}, nil
	}

	cfg := defaultConfig()
	cfg.maxBufferSize = conservativeOutputBufferSize * 2
	cli := &Client{ctx: ctx, config: cfg}
	got, err := cli.VerifyData(VerifyDataRequest{Flags: SignCMS})
	if err != nil {
		t.Fatalf("VerifyData failed: %v", err)
	}
	if string(got.Data) != "data" || got.VerifyInfo != "info" || string(got.Cert) != "cert" {
		t.Fatalf("VerifyData returned %+v", got)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}

	first := calls[0]
	if first.DataCapacity != wantDataOutput || first.InfoCapacity != wantInfoOutput || first.CertCapacity != wantCertOutput {
		t.Fatalf("first capacities = data:%d info:%d cert:%d", first.DataCapacity, first.InfoCapacity, first.CertCapacity)
	}
	second := calls[1]
	if second.DataCapacity != wantDataOutput+1 || second.InfoCapacity != wantInfoOutput+2 || second.CertCapacity != wantCertOutput+3 {
		t.Fatalf("second capacities = data:%d info:%d cert:%d", second.DataCapacity, second.InfoCapacity, second.CertCapacity)
	}
}

func TestVerifyDataGrowsOutputsToLengthsReportedWithOK(t *testing.T) {
	ctx := &fakeNativeContext{}
	var calls []kalkancrypt.VerifyDataCall
	ctx.verifyDataFunc = func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
		calls = append(calls, call)
		if len(calls) == 1 {
			return kalkancrypt.VerifyResult{
				Code:    uint64(ErrorOK),
				Data:    repeatedBytes('d', call.DataCapacity),
				DataLen: call.DataCapacity + 1,
				Info:    repeatedBytes('i', call.InfoCapacity),
				InfoLen: call.InfoCapacity + 2,
				Cert:    repeatedBytes('c', call.CertCapacity),
				CertLen: call.CertCapacity + 3,
			}, nil
		}

		return kalkancrypt.VerifyResult{
			Code:    uint64(ErrorOK),
			Data:    []byte("data"),
			DataLen: len("data"),
			Info:    []byte("info"),
			InfoLen: len("info"),
			Cert:    []byte("cert"),
			CertLen: len("cert"),
		}, nil
	}

	cli := &Client{ctx: ctx, config: config{
		bufferSize:    conservativeOutputBufferSize,
		maxBufferSize: conservativeOutputBufferSize * 2,
	}}
	got, err := cli.VerifyData(VerifyDataRequest{Flags: SignCMS})
	if err != nil {
		t.Fatalf("VerifyData failed: %v", err)
	}
	if string(got.Data) != "data" || got.VerifyInfo != "info" || string(got.Cert) != "cert" {
		t.Fatalf("VerifyData returned %+v", got)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}

	second := calls[1]
	if second.DataCapacity != conservativeOutputBufferSize+1 ||
		second.InfoCapacity != conservativeOutputBufferSize+2 ||
		second.CertCapacity != conservativeOutputBufferSize+3 {
		t.Fatalf("second capacities = data:%d info:%d cert:%d", second.DataCapacity, second.InfoCapacity, second.CertCapacity)
	}
}

func TestVerifyDataReturnsBufferTooSmallWhenReportedOutputsCannotGrow(t *testing.T) {
	ctx := &fakeNativeContext{}
	ctx.verifyDataFunc = func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
		return kalkancrypt.VerifyResult{
			Code:    uint64(ErrorBufferTooSmall),
			DataLen: call.DataCapacity + 1,
			InfoLen: call.InfoCapacity + 1,
			CertLen: call.CertCapacity + 1,
		}, nil
	}

	cli := &Client{ctx: ctx, config: config{
		bufferSize:    conservativeOutputBufferSize,
		maxBufferSize: conservativeOutputBufferSize,
	}}
	_, err := cli.VerifyData(VerifyDataRequest{Flags: SignCMS})
	if err == nil {
		t.Fatal("VerifyData unexpectedly succeeded")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
}

func TestVerifyDataDoesNotReturnUnusedDataBuffer(t *testing.T) {
	tests := []struct {
		name  string
		flags Flag
	}{
		{name: "detached CMS", flags: SignCMS | DetachedData},
		{name: "draft signature", flags: SignDraft},
		{name: "signature file", flags: SignCMS | InFile},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &fakeNativeContext{
				verifyDataFunc: func(kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
					return kalkancrypt.VerifyResult{
						Code:    uint64(ErrorOK),
						Data:    []byte("unused"),
						DataLen: len("unused"),
						Info:    []byte("info"),
						InfoLen: len("info"),
					}, nil
				},
			}

			client := &Client{ctx: ctx, config: defaultConfig()}
			got, err := client.VerifyData(VerifyDataRequest{
				Flags:        test.flags,
				Signature:    []byte("signature-or-path"),
				DataCapacity: 128,
			})
			if err != nil {
				t.Fatalf("VerifyData failed: %v", err)
			}
			if got.Data != nil {
				t.Fatalf("Data = %x, want nil", got.Data)
			}
		})
	}
}
