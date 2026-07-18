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

func TestCheckNativeInputLength(t *testing.T) {
	tests := []struct {
		name    string
		length  int64
		wantErr string
	}{
		{name: "negative", length: -1, wantErr: "negative input length"},
		{name: "zero", length: 0},
		{name: "maximum", length: math.MaxInt32},
		{name: "overflow", length: int64(math.MaxInt32) + 1, wantErr: "overflows native C int"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkNativeInputLength(test.length)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("checkNativeInputLength(%d) returned error: %v", test.length, err)
				}

				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("checkNativeInputLength(%d) error = %v, want %q", test.length, err, test.wantErr)
			}
		})
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

func TestOutputBufferAttemptsDoNotShareContents(t *testing.T) {
	first, err := outputBuffer(8)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		first[i] = 0xff
	}

	second, err := outputBuffer(8)
	if err != nil {
		t.Fatal(err)
	}
	if &first[0] == &second[0] {
		t.Fatal("separate live output buffers share the same backing storage")
	}
	if !bytes.Equal(second, make([]byte, len(second))) {
		t.Fatalf("second output buffer = %x, want zeroed bytes", second)
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

func TestBoundedBytesReturnsCapacityLimitedView(t *testing.T) {
	source := []byte("abcdef")

	short := boundedBytes(source, 3)
	if string(short) != "abc" {
		t.Fatalf("short output = %q, want abc", short)
	}
	if len(short) != 3 || cap(short) != 3 {
		t.Fatalf("short output len/cap = %d/%d, want 3/3", len(short), cap(short))
	}
	short[0] = 'x'
	if source[0] != 'x' {
		t.Fatal("boundedBytes copied the source instead of returning its bounded view")
	}
	if exact := boundedBytes(source, len(source)); string(exact) != "xbcdef" || cap(exact) != len(exact) {
		t.Fatalf("exact output = %q len/cap=%d/%d, want xbcdef with equal len/cap", exact, len(exact), cap(exact))
	}
	if overflow := boundedBytes(source, len(source)+100); string(overflow) != "xbcdef" || cap(overflow) != len(source) {
		t.Fatalf("overflow output = %q len/cap=%d/%d, want xbcdef with source capacity", overflow, len(overflow), cap(overflow))
	}
	if empty := boundedBytes(source, 0); len(empty) != 0 {
		t.Fatalf("empty output = %v, want empty slice", empty)
	}
	if negative := boundedBytes(source, -1); len(negative) != 0 {
		t.Fatalf("negative output = %v, want empty slice", negative)
	}
}

func TestBoundedBytesPreservesBinaryZeroBytes(t *testing.T) {
	source := []byte{1, 0, 2, 0}
	got := boundedBytes(source, len(source))
	if !bytes.Equal(got, source) {
		t.Fatalf("binary output = %v, want %v", got, source)
	}
	if len(got) != cap(got) {
		t.Fatalf("binary output len/cap = %d/%d, want equal", len(got), cap(got))
	}
}

func TestBytesBeforeNULTerminatorKeepsCStringPrefix(t *testing.T) {
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
			if got := bytesBeforeNULTerminator(tc.input); string(got) != tc.want {
				t.Fatalf("bytesBeforeNULTerminator(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
