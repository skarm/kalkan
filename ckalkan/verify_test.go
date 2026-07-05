package ckalkan

import (
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestVerifyDataRetriesDataInfoAndCertificateBuffers(t *testing.T) {
	const (
		wantDataOutput = 64 << 10
		wantInfoOutput = 4 << 10
		wantCertOutput = 8 << 10
	)

	ctx := &fakeNativeContext{}
	var capacities []kalkancrypt.VerifyDataCall
	ctx.verifyDataFunc = func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
		capacities = append(capacities, call)
		if len(capacities) == 1 {
			return kalkancrypt.VerifyResult{
				Code:    uint64(ErrorBufferTooSmall),
				DataLen: wantDataOutput + 1,
				InfoLen: wantInfoOutput + 2,
				CertLen: wantCertOutput + 3,
			}, nil
		}
		return kalkancrypt.VerifyResult{
			Code: uint64(ErrorOK),
			Data: []byte("data"),
			Info: []byte("info\x00unused"),
			Cert: []byte("cert"),
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
	if len(capacities) != 2 {
		t.Fatalf("calls = %d, want 2", len(capacities))
	}
	first := capacities[0]
	if first.DataCapacity != wantDataOutput || first.InfoCapacity != wantInfoOutput || first.CertCapacity != wantCertOutput {
		t.Fatalf("first capacities = data:%d info:%d cert:%d", first.DataCapacity, first.InfoCapacity, first.CertCapacity)
	}
	second := capacities[1]
	if second.DataCapacity != wantDataOutput+1 || second.InfoCapacity != wantInfoOutput+2 || second.CertCapacity != wantCertOutput+3 {
		t.Fatalf("second capacities = data:%d info:%d cert:%d", second.DataCapacity, second.InfoCapacity, second.CertCapacity)
	}
}

func TestVerifyDataRetriesWhenOKReportsOversizedOutput(t *testing.T) {
	ctx := &fakeNativeContext{}
	var capacities []kalkancrypt.VerifyDataCall
	ctx.verifyDataFunc = func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
		capacities = append(capacities, call)
		if len(capacities) == 1 {
			return kalkancrypt.VerifyResult{
				Code:    uint64(ErrorOK),
				Data:    bytesOf('d', call.DataCapacity),
				DataLen: call.DataCapacity + 1,
				Info:    bytesOf('i', call.InfoCapacity),
				InfoLen: call.InfoCapacity + 2,
				Cert:    bytesOf('c', call.CertCapacity),
				CertLen: call.CertCapacity + 3,
			}, nil
		}

		return kalkancrypt.VerifyResult{
			Code: uint64(ErrorOK),
			Data: []byte("data"),
			Info: []byte("info"),
			Cert: []byte("cert"),
		}, nil
	}

	cli := &Client{ctx: ctx, config: config{bufferSize: conservativeOutputBufferSize, maxBufferSize: conservativeOutputBufferSize * 2}}
	got, err := cli.VerifyData(VerifyDataRequest{Flags: SignCMS})
	if err != nil {
		t.Fatalf("VerifyData failed: %v", err)
	}
	if string(got.Data) != "data" || got.VerifyInfo != "info" || string(got.Cert) != "cert" {
		t.Fatalf("VerifyData returned %+v", got)
	}
	if len(capacities) != 2 {
		t.Fatalf("calls = %d, want 2", len(capacities))
	}
	second := capacities[1]
	if second.DataCapacity != conservativeOutputBufferSize+1 || second.InfoCapacity != conservativeOutputBufferSize+2 || second.CertCapacity != conservativeOutputBufferSize+3 {
		t.Fatalf("second capacities = data:%d info:%d cert:%d", second.DataCapacity, second.InfoCapacity, second.CertCapacity)
	}
}

func TestVerifyDataReturnsBufferTooSmallWhenNoBufferCanGrow(t *testing.T) {
	ctx := &fakeNativeContext{}
	ctx.verifyDataFunc = func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
		return kalkancrypt.VerifyResult{
			Code:    uint64(ErrorBufferTooSmall),
			DataLen: call.DataCapacity + 1,
			InfoLen: call.InfoCapacity + 1,
			CertLen: call.CertCapacity + 1,
		}, nil
	}

	cli := &Client{ctx: ctx, config: config{bufferSize: conservativeOutputBufferSize, maxBufferSize: conservativeOutputBufferSize}}
	_, err := cli.VerifyData(VerifyDataRequest{Flags: SignCMS})
	if err == nil {
		t.Fatal("VerifyData unexpectedly succeeded")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
}
