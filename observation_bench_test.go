package kalkan

import (
	"context"
	"testing"
)

func BenchmarkWithOperationsDiagnosticsDisabled(b *testing.B) {
	client := &Client{session: newNativeBackend(&fakeSDK{})}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if err := withOperations(client, ctx, "Init", func(native sessionInitializer) error {
			return native.Init()
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWithOperationsResultDiagnosticsDisabled(b *testing.B) {
	client := &Client{session: newNativeBackend(&fakeSDK{})}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		_, err := withOperationsResult(client, ctx, "Init", func(native sessionInitializer) (int, error) {
			return 1, native.Init()
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
