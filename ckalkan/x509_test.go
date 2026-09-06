package ckalkan

import (
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestX509RejectsOutOfRangeEnumsBeforeNativeCall(t *testing.T) {
	methods := []struct {
		name  string
		valid int
		call  func(*Client, int) error
	}{
		{name: "certificate file type", valid: int(CertCA), call: func(c *Client, value int) error {
			return c.X509LoadCertificateFromFile("certificate.pem", CertType(value))
		}},
		{name: "certificate buffer format", valid: int(CertPEM), call: func(c *Client, value int) error {
			return c.X509LoadCertificateFromBuffer([]byte("certificate"), CertFormat(value))
		}},
		{name: "certificate export format", valid: int(CertPEM), call: func(c *Client, value int) error {
			_, err := c.X509ExportCertificateFromStore("", CertFormat(value))
			return err
		}},
		{name: "certificate property", valid: int(CertPropSubjectDN), call: func(c *Client, value int) error {
			_, err := c.X509CertificateGetInfo([]byte("certificate"), CertProp(value))
			return err
		}},
		{name: "validation type", valid: int(UseNothing), call: func(c *Client, value int) error {
			_, err := c.X509ValidateCertificate(ValidateCertificateRequest{ValidationType: ValidationType(value)})
			return err
		}},
	}
	for _, method := range methods {
		t.Run(method.name, func(t *testing.T) {
			values := []int{-1}
			if strconv.IntSize > 32 {
				overflow := int64(maxNativeCInt) + 1
				aliased := int64(method.valid) + 1<<32
				values = append(values, int(overflow), int(aliased))
			}
			for _, value := range values {
				ctx := &fakeNativeContext{clearErrorFunc: func() { t.Fatal("invalid enum reached native context") }}
				client := &Client{ctx: ctx, config: defaultConfig()}
				if err := method.call(client, value); err == nil || !strings.Contains(err.Error(), "native C int") {
					t.Fatalf("value %d: error = %v, want native C int range rejection", value, err)
				}
			}
		})
	}
}

func TestNativeEnumConversionPreservesRangeBoundaries(t *testing.T) {
	for _, value := range []int{0, maxNativeCInt} {
		got, err := enumToNativeInt("enum", value)
		if err != nil || got != value {
			t.Fatalf("enumToNativeInt(%d) = %d, %v", value, got, err)
		}
	}
}

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
	got, err := cli.X509ValidateCertificate(ValidateCertificateRequest{Flags: NoCheckCertTime | GetOCSPResponse})
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
	if second.InfoCapacity != wantInfoOutput*2 || second.OCSPCapacity != wantOCSPOutput*2 {
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
	got, err := cli.X509ValidateCertificate(ValidateCertificateRequest{Flags: NoCheckCertTime | GetOCSPResponse})
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
	if second.InfoCapacity != conservativeOutputBufferSize*2 || second.OCSPCapacity != conservativeOutputBufferSize*2 {
		t.Fatalf("second capacities = info:%d ocsp:%d", second.InfoCapacity, second.OCSPCapacity)
	}
}

func TestValidateCertificateIgnoresInactiveOCSPOutput(t *testing.T) {
	for _, test := range []struct {
		name   string
		data   []byte
		length int
	}{
		{name: "unchanged native buffer", data: make([]byte, initialCertOutputBuffer), length: initialCertOutputBuffer},
		{name: "negative length", length: -1},
		{name: "inconsistent length", data: []byte("ocsp"), length: 3},
		{name: "length over output limit", length: DefaultMaxOutputBufferSize + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			ctx := &fakeNativeContext{
				validateCertificateFunc: func(call kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
					calls++
					if call.OCSPCapacity <= 0 {
						t.Fatal("native OCSP buffer must remain allocated for SDK compatibility")
					}
					return kalkancrypt.ValidateResult{
						Code: uint64(ErrorOK), Info: []byte("valid"), InfoLen: len("valid"),
						OCSP: test.data, OCSPLen: test.length,
					}, nil
				},
			}
			client := &Client{ctx: ctx, config: defaultConfig()}
			got, err := client.X509ValidateCertificate(ValidateCertificateRequest{})
			if err != nil || got.Info != "valid" || got.OCSPResponse != nil {
				t.Fatalf("X509ValidateCertificate = %+v, %v, want valid info and nil OCSP response", got, err)
			}
			if calls != 1 {
				t.Fatalf("native calls = %d, want 1", calls)
			}
		})
	}
}

func TestValidateCertificateDoesNotGrowInactiveOCSPBuffer(t *testing.T) {
	for _, reportedLength := range []int{-1, 16, DefaultMaxOutputBufferSize + 1} {
		var calls []kalkancrypt.ValidateCertificateCall
		ctx := &fakeNativeContext{
			validateCertificateFunc: func(call kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
				calls = append(calls, call)
				if len(calls) == 1 {
					// No useful info length: only the active info buffer must grow,
					// regardless of what the inactive OCSP length contains.
					return kalkancrypt.ValidateResult{Code: uint64(ErrorBufferTooSmall), OCSPLen: reportedLength}, nil
				}
				return kalkancrypt.ValidateResult{Code: uint64(ErrorOK), Info: []byte("valid"), InfoLen: len("valid"), OCSPLen: reportedLength}, nil
			},
		}
		client := &Client{ctx: ctx, config: config{maxBufferSize: 16}}
		got, err := client.X509ValidateCertificate(ValidateCertificateRequest{OutputCapacity: 8, OCSPCapacity: 16})
		if err != nil || got.Info != "valid" || got.OCSPResponse != nil {
			t.Fatalf("inactive OCSP length %d: X509ValidateCertificate = %+v, %v", reportedLength, got, err)
		}
		if len(calls) != 2 || calls[1].InfoCapacity != 16 || calls[1].OCSPCapacity != 16 {
			t.Fatalf("inactive OCSP length %d: native calls = %+v, want only info buffer to grow", reportedLength, calls)
		}
	}
}
