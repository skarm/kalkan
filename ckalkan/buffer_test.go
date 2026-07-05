package ckalkan

import (
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestCallListRetriesAfterBufferTooSmall(t *testing.T) {
	ctx := &fakeNativeContext{}
	var capacities []int
	ctx.getTokensFunc = func(_ uint64, capacity int) (kalkancrypt.ListResult, error) {
		capacities = append(capacities, capacity)
		if len(capacities) == 1 {
			return kalkancrypt.ListResult{
				Code: uint64(ErrorBufferTooSmall),
			}, nil
		}
		return kalkancrypt.ListResult{
			Code:  uint64(ErrorOK),
			Data:  "token-a;token-b",
			Count: 2,
		}, nil
	}

	cli := &Client{ctx: ctx, config: defaultConfig()}
	tokens, err := cli.GetTokens(StorePKCS12)
	if err != nil {
		t.Fatalf("GetTokens failed: %v", err)
	}
	if tokens.Data != "token-a;token-b" || tokens.Count != 2 {
		t.Fatalf("GetTokens returned %+v", tokens)
	}
	if want := []int{defaultListBufferSize, defaultListBufferSize * 2}; !equalInts(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
	}
}

func TestWithListBufferSizeIsInitialAllocationNotSafetyLimit(t *testing.T) {
	cfg := defaultConfig()
	WithListBufferSize(conservativeOutputBufferSize)(&cfg)
	WithMaxBufferSize(conservativeOutputBufferSize * 4)(&cfg)

	cli := &Client{config: cfg}
	var capacities []int
	_, err := cli.callListLocked(func(capacity int) (kalkancrypt.ListResult, error) {
		capacities = append(capacities, capacity)
		if len(capacities) == 1 {
			return kalkancrypt.ListResult{Code: uint64(ErrorBufferTooSmall)}, nil
		}

		return kalkancrypt.ListResult{Code: uint64(ErrorOK), Data: "token-a", Count: 1}, nil
	})
	if err != nil {
		t.Fatalf("callListLocked failed: %v", err)
	}
	if want := []int{conservativeOutputBufferSize, conservativeOutputBufferSize * 2}; !equalInts(capacities, want) {
		t.Fatalf("capacities = %v, want growth beyond WithListBufferSize initial allocation %v", capacities, want)
	}
}

func TestCallListReturnsBufferTooSmallWhenCapacityCannotGrow(t *testing.T) {
	var calls int
	cli := &Client{config: config{listBufferSize: conservativeOutputBufferSize, maxBufferSize: conservativeOutputBufferSize}}

	_, err := cli.callListLocked(func(capacity int) (kalkancrypt.ListResult, error) {
		calls++
		return kalkancrypt.ListResult{Code: uint64(ErrorBufferTooSmall)}, nil
	})
	if err == nil {
		t.Fatal("callListLocked unexpectedly succeeded")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestCallBufferHandlesSmallExactAndLargerOutputs(t *testing.T) {
	tests := []struct {
		name       string
		firstCode  ErrorCode
		firstLen   int
		secondData []byte
		wantCaps   []int
	}{
		{
			name:       "smaller than initial",
			secondData: []byte("small"),
			wantCaps:   []int{conservativeOutputBufferSize},
		},
		{
			name:       "exact initial capacity",
			secondData: bytesOf('x', conservativeOutputBufferSize),
			wantCaps:   []int{conservativeOutputBufferSize},
		},
		{
			name:       "larger than initial",
			firstCode:  ErrorBufferTooSmall,
			firstLen:   conservativeOutputBufferSize + 17,
			secondData: []byte("grown"),
			wantCaps:   []int{conservativeOutputBufferSize, conservativeOutputBufferSize + 17},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var capacities []int
			cli := &Client{config: config{bufferSize: 1, maxBufferSize: conservativeOutputBufferSize * 4}}
			got, err := cli.callBufferLocked(func(capacity int) (kalkancrypt.BufferResult, error) {
				capacities = append(capacities, capacity)
				if test.firstCode != 0 && len(capacities) == 1 {
					return kalkancrypt.BufferResult{Code: uint64(test.firstCode), OutLen: test.firstLen}, nil
				}
				return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: test.secondData, OutLen: len(test.secondData)}, nil
			})
			if err != nil {
				t.Fatalf("callBufferLocked failed: %v", err)
			}
			if string(got) != string(test.secondData) {
				t.Fatalf("output = %q, want %q", got, test.secondData)
			}
			if !equalInts(capacities, test.wantCaps) {
				t.Fatalf("capacities = %v, want %v", capacities, test.wantCaps)
			}
		})
	}
}

func TestCallBufferReturnsBufferTooSmallWhenCapacityCannotGrow(t *testing.T) {
	var calls int
	cli := &Client{config: config{bufferSize: conservativeOutputBufferSize, maxBufferSize: conservativeOutputBufferSize}}

	_, err := cli.callBufferLocked(func(capacity int) (kalkancrypt.BufferResult, error) {
		calls++
		return kalkancrypt.BufferResult{Code: uint64(ErrorBufferTooSmall), OutLen: capacity + 1}, nil
	})
	if err == nil {
		t.Fatal("callBufferLocked unexpectedly succeeded")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestCallBufferRetriesWhenOKReportsOversizedOutput(t *testing.T) {
	var capacities []int
	cli := &Client{config: config{bufferSize: conservativeOutputBufferSize, maxBufferSize: conservativeOutputBufferSize * 2}}

	got, err := cli.callBufferLocked(func(capacity int) (kalkancrypt.BufferResult, error) {
		capacities = append(capacities, capacity)
		if len(capacities) == 1 {
			return kalkancrypt.BufferResult{
				Code:   uint64(ErrorOK),
				Data:   bytesOf('x', capacity),
				OutLen: capacity + 1,
			}, nil
		}

		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("complete"), OutLen: len("complete")}, nil
	})
	if err != nil {
		t.Fatalf("callBufferLocked failed: %v", err)
	}
	if string(got) != "complete" {
		t.Fatalf("output = %q, want complete retry output", got)
	}
	if want := []int{conservativeOutputBufferSize, conservativeOutputBufferSize + 1}; !equalInts(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
	}
}

func TestCallBufferRetriesAfterBufferTooSmall(t *testing.T) {
	ctx := &fakeNativeContext{}
	var calls int
	ctx.hashDataFunc = func(string, int, []byte, int) (kalkancrypt.BufferResult, error) {
		calls++
		if calls == 1 {
			return kalkancrypt.BufferResult{Code: uint64(ErrorBufferTooSmall), OutLen: conservativeOutputBufferSize + 1}, nil
		}
		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("HASH"), OutLen: 4}, nil
	}

	cli := &Client{ctx: ctx, config: defaultConfig()}
	hash, err := cli.HashData(SHA256, 0, []byte("abc"))
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}
	if string(hash) != "HASH" {
		t.Fatalf("HashData = %q, want HASH", hash)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestNormalizeConfiguredBufferSizeCases(t *testing.T) {
	tests := []struct {
		name     string
		value    int
		fallback int
		want     int
	}{
		{name: "uses default when both inputs are empty", want: conservativeOutputBufferSize},
		{name: "uses fallback", fallback: conservativeOutputBufferSize + 1, want: conservativeOutputBufferSize + 1},
		{name: "value overrides fallback", value: conservativeOutputBufferSize + 2, fallback: conservativeOutputBufferSize + 1, want: conservativeOutputBufferSize + 2},
		{name: "clamps tiny configured value", value: 1, fallback: conservativeOutputBufferSize + 1, want: conservativeOutputBufferSize},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeConfiguredBufferSize(test.value, test.fallback); got != test.want {
				t.Fatalf("normalizeConfiguredBufferSize(%d, %d) = %d, want %d", test.value, test.fallback, got, test.want)
			}
		})
	}
}

func TestGrowCapacityCases(t *testing.T) {
	tests := []struct {
		name      string
		current   int
		requested int
		maximum   int
		want      int
	}{
		{name: "doubles when requested is smaller", current: 1024, requested: 512, maximum: 4096, want: 2048},
		{name: "uses requested when larger than double", current: 1024, requested: 3000, maximum: 4096, want: 3000},
		{name: "caps at maximum", current: conservativeOutputBufferSize, requested: conservativeOutputBufferSize * 3, maximum: conservativeOutputBufferSize * 2, want: conservativeOutputBufferSize * 2},
		{name: "does not grow at maximum", current: conservativeOutputBufferSize * 2, requested: conservativeOutputBufferSize * 3, maximum: conservativeOutputBufferSize * 2, want: conservativeOutputBufferSize * 2},
		{name: "raises tiny maximum to conservative output size", current: 1024, requested: conservativeOutputBufferSize + 1, maximum: 1, want: conservativeOutputBufferSize},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := growCapacity(test.current, test.requested, test.maximum); got != test.want {
				t.Fatalf("growCapacity(%d, %d, %d) = %d, want %d", test.current, test.requested, test.maximum, got, test.want)
			}
		})
	}
}
