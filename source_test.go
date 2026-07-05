package kalkan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestSourceConstructorsMarkExplicitSourcesAsSet(t *testing.T) {
	if (Source{}).isSet() {
		t.Fatal("zero-value Source is set, want missing source")
	}

	sources := []Source{
		Bytes(nil),
		Bytes([]byte{}),
		Base64(nil),
		PEM(nil),
		DER(nil),
		File(""),
	}

	for _, source := range sources {
		if !source.isSet() {
			t.Fatalf("%#v is not set, want constructor-created Source to be set", source)
		}
		if source.isZero() {
			t.Fatalf("%#v is zero, want constructor-created Source to be distinguishable from missing", source)
		}
	}
}

func TestSourceConstructorsUseCallerInput(t *testing.T) {
	input := []byte("original")
	sources := []Source{
		Bytes(input),
		Base64(input),
		PEM(input),
		DER(input),
	}

	input[0] = 'X'

	for _, source := range sources {
		got, err := source.bytesOrPath()
		if err != nil {
			t.Fatalf("bytesOrPath returned error: %v", err)
		}
		if string(got) != "Xriginal" {
			t.Fatalf("source data = %q, want caller input without cloning", got)
		}
	}
}

func TestFileSourcePathValidation(t *testing.T) {
	dir := t.TempDir()
	regularPath := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(regularPath, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}

	tests := []struct {
		name string
		path string
		want string
		err  string
	}{
		{name: "empty", path: "", err: "file source path is empty"},
		{name: "whitespace", path: " \t\n ", want: " \t\n "},
		{name: "embedded NUL", path: "a\x00b", err: "NUL"},
		{name: "preserve whitespace", path: " \t" + regularPath + "\n", want: " \t" + regularPath + "\n"},
		{name: "missing path", path: filepath.Join(dir, "missing.txt"), want: filepath.Join(dir, "missing.txt")},
		{name: "directory", path: dir, want: dir},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := File(test.path).bytesOrPath()
			if test.err != "" {
				if err == nil || !strings.Contains(err.Error(), test.err) {
					t.Fatalf("bytesOrPath error = %v, want %q", err, test.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("bytesOrPath returned error: %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("file source path = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFileSourceValidationRunsBeforeNativeCall(t *testing.T) {
	t.Run("Hash", func(t *testing.T) {
		native := &fakeNative{
			hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
				t.Fatal("Hash called native HashData with invalid file source")
				return nil, nil
			},
		}
		client := &Client{library: native}

		_, err := client.Hash(context.Background(), HashRequest{Data: File("")})
		if err == nil || !strings.Contains(err.Error(), "file source path is empty") {
			t.Fatalf("Hash error = %v, want file source path validation error", err)
		}
	})

	t.Run("SignCMS", func(t *testing.T) {
		native := &fakeNative{
			signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
				t.Fatal("SignCMS called native SignData with invalid file source")
				return nil, nil
			},
		}
		client := &Client{library: native}

		_, err := client.SignCMS(context.Background(), SignCMSRequest{Data: File("a\x00b")})
		if err == nil || !strings.Contains(err.Error(), "NUL") {
			t.Fatalf("SignCMS error = %v, want file source NUL validation error", err)
		}
	})

	t.Run("VerifyCMS", func(t *testing.T) {
		signaturePath := filepath.Join(t.TempDir(), "signature.cms")
		if err := os.WriteFile(signaturePath, []byte("cms"), 0o600); err != nil {
			t.Fatalf("write signature file source: %v", err)
		}

		native := &fakeNative{
			verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
				t.Fatal("VerifyCMS called native VerifyData with invalid detached file source")
				return ckalkan.VerifyDataResult{}, nil
			},
		}
		client := &Client{library: native}

		_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
			Signature: File(signaturePath),
			Data:      File(""),
			Detached:  true,
		})
		if err == nil || !strings.Contains(err.Error(), "file source path is empty") {
			t.Fatalf("VerifyCMS error = %v, want file source path validation error", err)
		}
	})
}

func TestFileSourcePassesPathToNativeWithoutRegularFilePreflight(t *testing.T) {
	dir := t.TempDir()

	t.Run("symlink", func(t *testing.T) {
		targetPath := filepath.Join(dir, "payload.txt")
		if err := os.WriteFile(targetPath, []byte("payload"), 0o600); err != nil {
			t.Fatalf("write target: %v", err)
		}

		linkPath := filepath.Join(dir, "payload-link.txt")
		if err := os.Symlink(targetPath, linkPath); err != nil {
			t.Skipf("symlink is unavailable: %v", err)
		}

		assertHashReceivesFilePath(t, linkPath)
	})

	t.Run("directory", func(t *testing.T) {
		assertHashReceivesFilePath(t, dir)
	})
}

func assertHashReceivesFilePath(t *testing.T, path string) {
	t.Helper()

	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			if string(data) != path {
				t.Fatalf("Hash data = %q, want path %q", data, path)
			}
			return []byte("digest"), nil
		},
	}
	client := &Client{library: native}

	if _, err := client.Hash(context.Background(), HashRequest{Data: File(path)}); err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
}
