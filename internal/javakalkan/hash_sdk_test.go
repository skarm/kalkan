package javakalkan_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/skarm/kalkan"
)

func TestJavaHash(t *testing.T) {
	client := openJavaIntegrationClient(t)
	ctx := context.Background()
	payload := []byte("abc")
	path := javaIntegrationFile(t, "payload.bin", payload)
	sha := sha256.Sum256(payload)

	for _, tc := range []struct {
		name      string
		algorithm kalkan.HashAlgorithm
		wantSize  int
		wantHex   string
	}{
		{name: "SHA256", algorithm: kalkan.SHA256, wantSize: 32, wantHex: hex.EncodeToString(sha[:])},
		// Captured independently from native Linux KalkanCrypt 2.0.13.
		{name: "GOST95", algorithm: kalkan.GOST95, wantSize: 32, wantHex: "f3134348c44fb1b2a277729e2285ebb5cb5e0f29c975bc753b70497c06a4d51d"},
		{name: "GOST2015_256", algorithm: kalkan.GOST2015_256, wantSize: 32, wantHex: "4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481"},
		{name: "GOST2015_512", algorithm: kalkan.GOST2015_512, wantSize: 64, wantHex: "28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var memoryDigest []byte
			for _, input := range []struct {
				name string
				data kalkan.Source
			}{
				{name: "bytes", data: kalkan.Bytes(payload)},
				{name: "file", data: kalkan.File(path)},
			} {
				t.Run(input.name, func(t *testing.T) {
					digest, err := client.Hash(ctx, kalkan.HashRequest{Algorithm: tc.algorithm, Data: input.data})
					if err != nil {
						t.Fatalf("Hash: %v", err)
					}
					if digest.Algorithm != tc.algorithm || len(digest.Data) != tc.wantSize {
						t.Fatalf("Hash = algorithm %d, %d bytes; want %d, %d bytes", digest.Algorithm, len(digest.Data), tc.algorithm, tc.wantSize)
					}
					if tc.wantHex != "" && hex.EncodeToString(digest.Data) != tc.wantHex {
						t.Fatalf("Hash(abc) = %x, want %s", digest.Data, tc.wantHex)
					}
					if input.name == "bytes" {
						memoryDigest = bytes.Clone(digest.Data)
					} else if !bytes.Equal(digest.Data, memoryDigest) {
						t.Fatal("file digest differs from in-memory digest")
					}
				})
			}
		})
	}

	t.Run("explicit empty input", func(t *testing.T) {
		digest, err := client.Hash(ctx, kalkan.HashRequest{Algorithm: kalkan.SHA256, Data: kalkan.Bytes(nil)})
		if err != nil {
			t.Fatalf("Hash(empty): %v", err)
		}
		want := sha256.Sum256(nil)
		if !bytes.Equal(digest.Data, want[:]) {
			t.Fatalf("Hash(empty) = %x, want %x", digest.Data, want)
		}
	})
}
