package javakalkan

import (
	"bytes"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

// Measures Go encoding overhead only, without starting the provider.
func BenchmarkBase64Output(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{{"1KiB", 1 << 10}, {"1MiB", 1 << 20}} {
		b.Run(tc.name, func(b *testing.B) {
			data := bytes.Repeat([]byte{0xa5}, tc.size)
			operation := New(Config{MaxOutputSize: 4 << 20}).WithContext(b.Context())
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := operation.outputBytes("SignCMS", data, ckalkan.OutBase64); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
