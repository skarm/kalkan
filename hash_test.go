package kalkan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestHashPassesRawInput(t *testing.T) {
	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			if algorithm != ckalkan.SHA256 {
				t.Fatalf("algorithm = %q, want SHA256", algorithm)
			}
			if flags != 0 {
				t.Fatalf("flags = %#x, want 0", flags)
			}
			if string(data) != "payload" {
				t.Fatalf("hash input = %q, want payload", data)
			}
			return []byte("digest"), nil
		},
	}
	client := &Client{library: native}

	digest, err := client.Hash(context.Background(), HashRequest{
		Algorithm: SHA256,
		Data:      Bytes([]byte("payload")),
	})
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if digest.Algorithm != SHA256 {
		t.Fatalf("digest algorithm = %d, want SHA256", digest.Algorithm)
	}
	if string(digest.Data) != "digest" {
		t.Fatalf("digest data = %q, want digest", digest.Data)
	}
}

func TestHashPassesFilePathAndEncodingFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.b64")
	if err := os.WriteFile(path, []byte("cGF5bG9hZA=="), 0o600); err != nil {
		t.Fatalf("write hash file source: %v", err)
	}

	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			if algorithm != ckalkan.GOST2015_512 {
				t.Fatalf("algorithm = %q, want GOST2015_512", algorithm)
			}
			wantFlags := ckalkan.InFile | ckalkan.InBase64
			if flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, wantFlags)
			}
			if string(data) != path {
				t.Fatalf("hash file input = %q, want path", data)
			}
			return []byte("digest"), nil
		},
	}
	client := &Client{library: native}

	_, err := client.Hash(context.Background(), HashRequest{
		Algorithm: GOST2015_512,
		Data:      File(path).WithEncoding(EncodingBase64),
	})
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
}

func TestHashRequiresData(t *testing.T) {
	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			t.Fatal("Hash called native HashData without Data source")
			return nil, nil
		},
	}
	client := &Client{library: native}

	_, err := client.Hash(context.Background(), HashRequest{})
	if err == nil || !strings.Contains(err.Error(), "hash data is required") {
		t.Fatalf("Hash error = %v, want missing hash data error", err)
	}
}

func TestHashAllowsExplicitEmptyData(t *testing.T) {
	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			if len(data) != 0 {
				t.Fatalf("hash data length = %d, want explicit empty payload", len(data))
			}
			return []byte("empty-digest"), nil
		},
	}
	client := &Client{library: native}

	digest, err := client.Hash(context.Background(), HashRequest{
		Data: Bytes(nil),
	})
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if string(digest.Data) != "empty-digest" {
		t.Fatalf("digest = %q, want empty-digest", digest.Data)
	}
}

func TestHashDoesNotCopyDigest(t *testing.T) {
	nativeDigest := []byte("digest")
	client := &Client{library: &fakeNative{
		hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
			return nativeDigest, nil
		},
	}}

	digest, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("payload"))})
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if !sameByteSliceBacking(digest.Data, nativeDigest) {
		t.Fatal("Hash cloned native digest output")
	}
}

func TestSignHashReturnsRawCMS(t *testing.T) {
	digest := testDigest()
	native := &fakeNative{
		signHashFunc: func(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error) {
			if alias != "signing-key" {
				t.Fatalf("alias = %q, want signing-key", alias)
			}
			wantFlags := ckalkan.SignCMS | ckalkan.OutDER | ckalkan.WithCert | ckalkan.NoCheckCertTime
			if flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, wantFlags)
			}
			if string(hash) != string(digest) {
				t.Fatalf("hash input = %x, want %x", hash, digest)
			}
			return []byte("raw-signed-hash"), nil
		},
	}
	client := &Client{library: native}

	cms, err := client.SignHash(context.Background(), SignHashRequest{
		Alias:                "signing-key",
		Digest:               digest,
		IncludeCertificate:   true,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignHash returned error: %v", err)
	}
	if string(cms.Data) != "raw-signed-hash" {
		t.Fatalf("signed hash data = %q, want raw-signed-hash", cms.Data)
	}
}

func TestSignHashUsesCallerDigest(t *testing.T) {
	digest := testDigest()
	mutated := testDigest()
	mutated[0] ^= 0xff
	enteredNative := make(chan struct{})
	releaseNative := make(chan struct{})
	hashSeen := make(chan []byte, 1)

	native := &fakeNative{
		signHashFunc: func(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error) {
			close(enteredNative)
			<-releaseNative
			hashSeen <- append([]byte(nil), hash...)
			return []byte("signed"), nil
		},
	}
	client := &Client{library: native}

	done := make(chan error, 1)
	go func() {
		_, err := client.SignHash(context.Background(), SignHashRequest{Digest: digest})
		done <- err
	}()

	<-enteredNative
	copy(digest, mutated)
	close(releaseNative)

	if err := <-done; err != nil {
		t.Fatalf("SignHash returned error: %v", err)
	}
	if got := <-hashSeen; string(got) != string(mutated) {
		t.Fatalf("native hash = %x, want caller digest without cloning", got)
	}
}

func TestSignHashCanRequestBase64Output(t *testing.T) {
	native := &fakeNative{
		signHashFunc: func(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error) {
			wantFlags := ckalkan.SignCMS | ckalkan.OutBase64
			if flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, wantFlags)
			}
			return []byte("base64-signed-hash"), nil
		},
	}
	client := &Client{library: native}

	cms, err := client.SignHash(context.Background(), SignHashRequest{
		Digest:       testDigest(),
		OutputFormat: CMSOutputBase64,
	})
	if err != nil {
		t.Fatalf("SignHash returned error: %v", err)
	}
	if string(cms.Data) != "base64-signed-hash" {
		t.Fatalf("signed hash data = %q, want base64-signed-hash", cms.Data)
	}
}

func TestSignHashRejectsUnknownOutputFormat(t *testing.T) {
	native := &fakeNative{
		signHashFunc: func(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error) {
			t.Fatal("SignHash called native SignHash for an invalid output format")
			return nil, nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignHash(context.Background(), SignHashRequest{
		Digest:       testDigest(),
		OutputFormat: CMSOutputFormat(99),
	})
	if err == nil || !strings.Contains(err.Error(), "unknown CMS output format 99") {
		t.Fatalf("SignHash error = %v, want unknown CMS output format error", err)
	}
}

func TestSignHashRejectsWrongDigestLength(t *testing.T) {
	native := &fakeNative{
		signHashFunc: func(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error) {
			t.Fatal("SignHash called native SignHash with digest length mismatch")
			return nil, nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignHash(context.Background(), SignHashRequest{
		Digest:          make([]byte, 32),
		DigestAlgorithm: GOST2015_512,
	})
	if err == nil || !strings.Contains(err.Error(), "digest length") {
		t.Fatalf("SignHash error = %v, want digest length mismatch error", err)
	}
}

func testDigest() []byte {
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}

	return digest
}
