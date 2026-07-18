package ckalkan

import (
	"slices"
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestCallListRetriesWithoutCStringTerminator(t *testing.T) {
	var bufferSizes []int
	cli := &Client{config: defaultConfig()}

	result, err := cli.callListLocked(func(bufferSize int) (kalkancrypt.ListResult, error) {
		bufferSizes = append(bufferSizes, bufferSize)
		if len(bufferSizes) == 1 {
			return kalkancrypt.ListResult{
				Code: uint64(ErrorOK),
				Data: string(repeatedBytes('x', bufferSize)),
			}, nil
		}

		return kalkancrypt.ListResult{Code: uint64(ErrorOK), Data: "token-a", Count: 1}, nil
	})
	if err != nil {
		t.Fatalf("callListLocked failed: %v", err)
	}
	if result.Data != "token-a" || result.Count != 1 {
		t.Fatalf("result = %+v, want token-a with count 1", result)
	}
	if want := []int{defaultListBufferSize, defaultListBufferSize * 2}; !slices.Equal(bufferSizes, want) {
		t.Fatalf("buffer sizes = %v, want %v", bufferSizes, want)
	}
}

func TestCallListRejectsUnterminatedOutputAtHardLimit(t *testing.T) {
	var calls int
	cli := &Client{config: config{
		listBufferSize: conservativeOutputBufferSize,
		maxBufferSize:  conservativeOutputBufferSize,
	}}

	_, err := cli.callListLocked(func(bufferSize int) (kalkancrypt.ListResult, error) {
		calls++

		return kalkancrypt.ListResult{
			Code: uint64(ErrorOK),
			Data: string(repeatedBytes('x', bufferSize)),
		}, nil
	})
	if err == nil {
		t.Fatal("callListLocked unexpectedly accepted an unterminated full buffer")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestWithListBufferSizeSetsInitialAllocation(t *testing.T) {
	cfg := defaultConfig()
	WithListBufferSize(conservativeOutputBufferSize)(&cfg)
	WithMaxBufferSize(conservativeOutputBufferSize * 4)(&cfg)

	cli := &Client{config: cfg}
	var bufferSizes []int
	_, err := cli.callListLocked(func(bufferSize int) (kalkancrypt.ListResult, error) {
		bufferSizes = append(bufferSizes, bufferSize)
		if len(bufferSizes) == 1 {
			return kalkancrypt.ListResult{Code: uint64(ErrorBufferTooSmall)}, nil
		}

		return kalkancrypt.ListResult{Code: uint64(ErrorOK), Data: "token-a", Count: 1}, nil
	})
	if err != nil {
		t.Fatalf("callListLocked failed: %v", err)
	}
	if want := []int{conservativeOutputBufferSize, conservativeOutputBufferSize * 2}; !slices.Equal(bufferSizes, want) {
		t.Fatalf("buffer sizes = %v, want %v", bufferSizes, want)
	}
}

func TestCallListRejectsHardLimitBelowInitialAllocation(t *testing.T) {
	var calls int
	cli := &Client{config: config{listBufferSize: defaultListBufferSize, maxBufferSize: conservativeOutputBufferSize}}

	_, err := cli.callListLocked(func(bufferSize int) (kalkancrypt.ListResult, error) {
		calls++
		t.Errorf("native list call received unsafe buffer size %d", bufferSize)
		return kalkancrypt.ListResult{}, nil
	})
	if err == nil {
		t.Fatal("callListLocked unexpectedly succeeded")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
	if calls != 0 {
		t.Fatalf("calls = %d, want no native call", calls)
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
			secondData: repeatedBytes('x', conservativeOutputBufferSize),
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
			got, err := cli.callBufferWithCapacityLocked(cli.config.outputInitialCapacity(defaultOutputBufferSize), func(capacity int) (kalkancrypt.BufferResult, error) {
				capacities = append(capacities, capacity)
				if test.firstCode != 0 && len(capacities) == 1 {
					return kalkancrypt.BufferResult{Code: uint64(test.firstCode), OutLen: test.firstLen}, nil
				}
				return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: test.secondData, OutLen: len(test.secondData)}, nil
			})
			if err != nil {
				t.Fatalf("callBufferWithCapacityLocked failed: %v", err)
			}
			if string(got) != string(test.secondData) {
				t.Fatalf("output = %q, want %q", got, test.secondData)
			}
			if !slices.Equal(capacities, test.wantCaps) {
				t.Fatalf("capacities = %v, want %v", capacities, test.wantCaps)
			}
		})
	}
}

func TestCallBufferStopsAtMaxSize(t *testing.T) {
	var calls int
	cli := &Client{config: config{bufferSize: conservativeOutputBufferSize, maxBufferSize: conservativeOutputBufferSize}}

	_, err := cli.callBufferWithCapacityLocked(cli.config.outputInitialCapacity(defaultOutputBufferSize), func(capacity int) (kalkancrypt.BufferResult, error) {
		calls++
		return kalkancrypt.BufferResult{Code: uint64(ErrorBufferTooSmall), OutLen: capacity + 1}, nil
	})
	if err == nil {
		t.Fatal("callBufferWithCapacityLocked unexpectedly succeeded")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorBufferTooSmall {
		t.Fatalf("error = %v, want ErrorBufferTooSmall", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestHardBufferLimitIsHonoredBelowConservativeInitialSize(t *testing.T) {
	const hardLimit = 1024

	var capacity int
	cli := &Client{config: config{maxBufferSize: hardLimit}}
	_, err := cli.callBufferWithCapacityLocked(cli.config.outputInitialCapacity(defaultOutputBufferSize), func(got int) (kalkancrypt.BufferResult, error) {
		capacity = got

		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
	})
	if err != nil {
		t.Fatalf("callBufferWithCapacityLocked failed: %v", err)
	}
	if capacity != hardLimit {
		t.Fatalf("initial capacity = %d, want hard limit %d", capacity, hardLimit)
	}
}

func TestCallBufferCanGrowPastDefaultSoftLimit(t *testing.T) {
	var capacities []int
	cli := &Client{config: defaultConfig()}

	got, err := cli.callBufferWithCapacityLocked(defaultSoftOutputBufferSize, func(capacity int) (kalkancrypt.BufferResult, error) {
		capacities = append(capacities, capacity)
		if len(capacities) == 1 {
			return kalkancrypt.BufferResult{
				Code:   uint64(ErrorBufferTooSmall),
				OutLen: defaultSoftOutputBufferSize + 17,
			}, nil
		}

		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("complete"), OutLen: len("complete")}, nil
	})
	if err != nil {
		t.Fatalf("callBufferWithCapacityLocked failed: %v", err)
	}
	if string(got) != "complete" {
		t.Fatalf("output = %q, want complete", got)
	}
	if want := []int{defaultSoftOutputBufferSize, defaultSoftOutputBufferSize + 17}; !slices.Equal(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
	}
}

func TestCallBufferRetriesOversizedOutput(t *testing.T) {
	var capacities []int
	cli := &Client{config: config{bufferSize: conservativeOutputBufferSize, maxBufferSize: conservativeOutputBufferSize * 2}}

	got, err := cli.callBufferWithCapacityLocked(cli.config.outputInitialCapacity(defaultOutputBufferSize), func(capacity int) (kalkancrypt.BufferResult, error) {
		capacities = append(capacities, capacity)
		if len(capacities) == 1 {
			return kalkancrypt.BufferResult{
				Code:   uint64(ErrorOK),
				Data:   repeatedBytes('x', capacity),
				OutLen: capacity + 1,
			}, nil
		}

		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("complete"), OutLen: len("complete")}, nil
	})
	if err != nil {
		t.Fatalf("callBufferWithCapacityLocked failed: %v", err)
	}
	if string(got) != "complete" {
		t.Fatalf("output = %q, want complete retry output", got)
	}
	if want := []int{conservativeOutputBufferSize, conservativeOutputBufferSize + 1}; !slices.Equal(capacities, want) {
		t.Fatalf("capacities = %v, want %v", capacities, want)
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
		{name: "honors tiny hard maximum", current: 1, requested: conservativeOutputBufferSize + 1, maximum: 1, want: 1},
		{name: "reported size crosses soft limit", current: defaultSoftOutputBufferSize, requested: defaultSoftOutputBufferSize + 1, want: defaultSoftOutputBufferSize + 1},
		{name: "blind growth pauses at soft limit", current: 40 << 20, want: defaultSoftOutputBufferSize},
		{name: "blind growth continues after soft limit", current: defaultSoftOutputBufferSize, want: defaultSoftOutputBufferSize * 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := growCapacity(test.current, test.requested, test.maximum); got != test.want {
				t.Fatalf("growCapacity(%d, %d, %d) = %d, want %d", test.current, test.requested, test.maximum, got, test.want)
			}
		})
	}
}

func FuzzOutputCapacityBounds(f *testing.F) {
	f.Add(0, 0, 0)
	f.Add(conservativeOutputBufferSize, conservativeOutputBufferSize+1, conservativeOutputBufferSize*2)
	f.Add(-1, int(^uint(0)>>1), 1)

	f.Fuzz(func(t *testing.T, initial, reported, maximum int) {
		limit := outputBufferLimit(maximum)
		current := boundedOutputCapacity(initial, maximum)
		if current <= 0 || current > limit {
			t.Fatalf("boundedOutputCapacity(%d, %d) = %d, want 1..%d", initial, maximum, current, limit)
		}

		next := growCapacity(current, reported, maximum)
		if next < current || next > limit {
			t.Fatalf("growCapacity(%d, %d, %d) = %d, want %d..%d", current, reported, maximum, next, current, limit)
		}
	})
}
