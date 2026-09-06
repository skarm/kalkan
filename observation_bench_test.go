package kalkan

import (
	"context"
	"testing"
)

func BenchmarkWithLockedLibraryDiagnosticsDisabled(b *testing.B) {
	client := &Client{library: &fakeNative{}}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if err := withLockedLibrary(client, ctx, "Init", func(native initializer) error {
			return native.Init()
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWithLockedLibraryResultDiagnosticsDisabled(b *testing.B) {
	client := &Client{library: &fakeNative{}}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		_, err := withLockedLibraryResult(client, ctx, "Init", func(native initializer) (int, error) {
			return 1, native.Init()
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
