package kalkancrypt

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

var benchmarkOutputBufferSink []byte

func TestOutputBufferRejectsInvalidCapacity(t *testing.T) {
	sizes := []int{0, -1}
	if strconv.IntSize > 32 {
		tooLarge := int64(math.MaxInt32) + 1
		sizes = append(sizes, int(tooLarge))
	}

	for _, size := range sizes {
		if _, err := outputBuffer(size); err == nil {
			t.Fatalf("outputBuffer(%d) unexpectedly succeeded", size)
		}
	}
}

func TestCheckNativeInputLengthRejectsInt32Overflow(t *testing.T) {
	if err := checkNativeInputLength(math.MaxInt32); err != nil {
		t.Fatalf("checkNativeInputLength(MaxInt32) returned error: %v", err)
	}
	if err := checkNativeInputLength(int64(math.MaxInt32) + 1); err == nil ||
		!strings.Contains(err.Error(), "overflows native C int") {
		t.Fatalf("checkNativeInputLength(MaxInt32+1) error = %v, want overflow error", err)
	}
}

func TestOutputBufferAllocatesRequestedCapacity(t *testing.T) {
	buf, err := outputBuffer(8)
	if err != nil {
		t.Fatalf("outputBuffer failed: %v", err)
	}
	if len(buf) != 8 {
		t.Fatalf("buffer length = %d, want 8", len(buf))
	}
	for i, value := range buf {
		if value != 0 {
			t.Fatalf("buffer[%d] = %d, want zeroed output buffer", i, value)
		}
	}
}

func BenchmarkOutputBufferCapacities(b *testing.B) {
	for _, size := range []int{128, 4 << 10, 8 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				buf, err := outputBuffer(size)
				if err != nil {
					b.Fatal(err)
				}

				benchmarkOutputBufferSink = buf
			}
		})
	}
}

func TestBoundedBytesOutputCases(t *testing.T) {
	source := []byte("abcdef")

	short := boundedBytes(source, 3)
	if string(short) != "abc" {
		t.Fatalf("short output = %q, want abc", short)
	}
	short[0] = 'x'
	if source[0] != 'a' {
		t.Fatal("boundedBytes returned a mutable view of the source buffer")
	}

	if exact := boundedBytes(source, len(source)); string(exact) != "abcdef" {
		t.Fatalf("exact output = %q, want abcdef", exact)
	}
	if overflow := boundedBytes(source, len(source)+100); string(overflow) != "abcdef" {
		t.Fatalf("overflow output = %q, want abcdef", overflow)
	}
	if empty := boundedBytes(source, 0); len(empty) != 0 {
		t.Fatalf("empty output = %v, want empty slice", empty)
	}
	if negative := boundedBytes(source, -1); len(negative) != 0 {
		t.Fatalf("negative output = %v, want empty slice", negative)
	}
}

func TestBoundedBytesPreservesZeroFilledBinaryOutput(t *testing.T) {
	source := []byte{0, 0, 0, 0}
	got := boundedBytes(source, len(source))
	if !bytes.Equal(got, source) {
		t.Fatalf("zero-filled output = %v, want %v", got, source)
	}
	if len(got) > 0 {
		got[0] = 1
	}
	if source[0] != 0 {
		t.Fatal("boundedBytes returned a mutable view of the source buffer")
	}
}

func TestTrimCStringBytesKeepsTextBeforeFirstTerminator(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{name: "plain bytes", input: []byte("plain"), want: "plain"},
		{name: "terminated string", input: []byte{'v', 'a', 'l', 'u', 'e', 0, 'g', 'a', 'r', 'b', 'a', 'g', 'e'}, want: "value"},
		{name: "empty c string", input: []byte{0, 'x'}, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := trimCStringBytes(tc.input); string(got) != tc.want {
				t.Fatalf("trimCStringBytes(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
