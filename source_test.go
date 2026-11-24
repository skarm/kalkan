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

func TestFileSourceValidatesPath(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) error
		want string
	}{
		{
			name: "Hash empty path",
			call: func(client *Client) error {
				_, err := client.Hash(context.Background(), HashRequest{Data: File("")})
				return err
			},
			want: "file source path is empty",
		},
		{
			name: "SignCMS embedded NUL",
			call: func(client *Client) error {
				_, err := client.SignCMS(context.Background(), SignCMSRequest{Data: File("a\x00b")})
				return err
			},
			want: "NUL",
		},
		{
			name: "VerifyCMS empty detached path",
			call: func(client *Client) error {
				_, err := client.VerifyCMS(context.Background(), VerifyCMSRequest{
					Signature: File("signature.cms"),
					Data:      File(""),
					Detached:  true,
				})
				return err
			},
			want: "file source path is empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			native := &fakeSDK{
				hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
					t.Error("Hash called native HashData with invalid file source")
					return nil, nil
				},
				signDataFunc: func(string, ckalkan.Flag, []byte, []byte) ([]byte, error) {
					t.Error("SignCMS called native SignData with invalid file source")
					return nil, nil
				},
				verifyDataFunc: func(ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
					t.Error("VerifyCMS called native VerifyData with invalid file source")
					return ckalkan.VerifyDataResult{}, nil
				},
			}
			client := &Client{session: newNativeBackend(native)}

			if err := test.call(client); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("operation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFileSourceDoesNotStatPath(t *testing.T) {
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

	native := &fakeSDK{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			if string(data) != path {
				t.Fatalf("Hash data = %q, want path %q", data, path)
			}
			return []byte("digest"), nil
		},
	}
	client := &Client{session: newNativeBackend(native)}

	if _, err := client.Hash(context.Background(), HashRequest{Data: File(path)}); err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
}

func TestSourceDescribePreservesPresenceKindAndEncoding(t *testing.T) {
	for _, test := range []struct {
		name      string
		source    Source
		set, file bool
		encoding  Encoding
		path      string
	}{
		{"absent", Source{}, false, false, EncodingAuto, ""},
		{"absent with encoding", Source{}.WithEncoding(EncodingDER), false, false, EncodingDER, ""},
		{"explicit empty", Bytes(nil), true, false, EncodingRaw, ""},
		{"empty file", File(""), true, true, EncodingAuto, ""},
		{"file with encoding", File("document.cms").WithEncoding(EncodingPEM), true, true, EncodingPEM, "document.cms"},
		{"unknown encoding", DER([]byte("der")).WithEncoding(Encoding(99)), true, false, Encoding(99), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := test.source.Describe()
			if got.Set != test.set || got.File != test.file || got.Encoding != test.encoding || got.Path != test.path {
				t.Fatalf("Describe = %+v, want set=%v file=%v encoding=%d path=%q", got, test.set, test.file, test.encoding, test.path)
			}
		})
	}
}

func TestSourceDescribeBorrowsDataWithoutChangingSource(t *testing.T) {
	data := []byte{0, 0xff, 2}
	source := Bytes(data)
	described := source.Describe()
	if !sameByteSliceBacking(described.Data, data) {
		t.Fatal("Describe copied the borrowed data")
	}
	described.Path, described.File, described.Set = "different", true, false
	got := source.Describe()
	if got.Path != "" || got.File || !got.Set || !sameByteSliceBacking(got.Data, data) {
		t.Fatalf("changing descriptor fields changed Source: %+v", got)
	}
}
