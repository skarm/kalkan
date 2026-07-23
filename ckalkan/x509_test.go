package ckalkan

import (
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestValidateCertificateRetriesInfoAndOCSPBuffers(t *testing.T) {
	const (
		wantInfoOutput = initialInfoOutputBuffer
		wantOCSPOutput = initialCertOutputBuffer
	)

	ctx := &fakeNativeContext{}
	var capacities []kalkancrypt.ValidateCertificateCall
	ctx.validateCertificateFunc = func(call kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
		capacities = append(capacities, call)
		if len(capacities) == 1 {
			return kalkancrypt.ValidateResult{
				Code:    uint64(ErrorBufferTooSmall),
				InfoLen: wantInfoOutput + 4,
				OCSPLen: wantOCSPOutput + 5,
			}, nil
		}
		return kalkancrypt.ValidateResult{
			Code:    uint64(ErrorOK),
			Info:    []byte("valid\x00"),
			InfoLen: len("valid\x00"),
			OCSP:    []byte("ocsp"),
			OCSPLen: len("ocsp"),
		}, nil
	}

	cfg := defaultConfig()
	cfg.maxBufferSize = conservativeOutputBufferSize * 2
	cli := &Client{ctx: ctx, config: cfg}
	got, err := cli.X509ValidateCertificate(ValidateCertificateRequest{Flags: NoCheckCertTime})
	if err != nil {
		t.Fatalf("X509ValidateCertificate failed: %v", err)
	}
	if got.Info != "valid" || string(got.OCSPResponse) != "ocsp" {
		t.Fatalf("X509ValidateCertificate returned %+v", got)
	}
	if len(capacities) != 2 {
		t.Fatalf("calls = %d, want 2", len(capacities))
	}
	first := capacities[0]
	if first.InfoCapacity != wantInfoOutput || first.OCSPCapacity != wantOCSPOutput {
		t.Fatalf("first capacities = info:%d ocsp:%d", first.InfoCapacity, first.OCSPCapacity)
	}
	second := capacities[1]
	if second.InfoCapacity != wantInfoOutput+4 || second.OCSPCapacity != wantOCSPOutput+5 {
		t.Fatalf("second capacities = info:%d ocsp:%d", second.InfoCapacity, second.OCSPCapacity)
	}
}

func TestValidateCertificateRetriesOversizedOutput(t *testing.T) {
	ctx := &fakeNativeContext{}
	var capacities []kalkancrypt.ValidateCertificateCall
	ctx.validateCertificateFunc = func(call kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
		capacities = append(capacities, call)
		if len(capacities) == 1 {
			return kalkancrypt.ValidateResult{
				Code:    uint64(ErrorOK),
				Info:    repeatedBytes('i', call.InfoCapacity),
				InfoLen: call.InfoCapacity + 4,
				OCSP:    repeatedBytes('o', call.OCSPCapacity),
				OCSPLen: call.OCSPCapacity + 5,
			}, nil
		}

		return kalkancrypt.ValidateResult{
			Code:    uint64(ErrorOK),
			Info:    []byte("valid"),
			InfoLen: len("valid"),
			OCSP:    []byte("ocsp"),
			OCSPLen: len("ocsp"),
		}, nil
	}

	cli := &Client{ctx: ctx, config: config{bufferSize: conservativeOutputBufferSize, maxBufferSize: conservativeOutputBufferSize * 2}}
	got, err := cli.X509ValidateCertificate(ValidateCertificateRequest{Flags: NoCheckCertTime})
	if err != nil {
		t.Fatalf("X509ValidateCertificate failed: %v", err)
	}
	if got.Info != "valid" || string(got.OCSPResponse) != "ocsp" {
		t.Fatalf("X509ValidateCertificate returned %+v", got)
	}
	if len(capacities) != 2 {
		t.Fatalf("calls = %d, want 2", len(capacities))
	}
	second := capacities[1]
	if second.InfoCapacity != conservativeOutputBufferSize+4 || second.OCSPCapacity != conservativeOutputBufferSize+5 {
		t.Fatalf("second capacities = info:%d ocsp:%d", second.InfoCapacity, second.OCSPCapacity)
	}
}
