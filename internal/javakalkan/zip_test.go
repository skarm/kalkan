package javakalkan

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestZIPInputBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   []string
		payload []byte
		limit   int64
	}{
		{"duplicate", []string{"data", "data"}, []byte("data"), 4096},
		{"case alias", []string{"data", "DATA"}, []byte("data"), 4096},
		{"traversal", []string{"../data"}, []byte("data"), 4096},
		{"absolute path", []string{"/data"}, []byte("data"), 4096},
		{"backslash", []string{"a\\data"}, []byte("data"), 4096},
		{"decompression limit", []string{"data"}, bytes.Repeat([]byte("compressible"), 1000), 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			w := zip.NewWriter(&b)
			for _, name := range tc.files {
				f, err := w.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.Write(tc.payload); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "input.zip")
			if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			c := New(Config{MaxInputSize: tc.limit}).WithContext(t.Context())
			if _, err := c.zipEntries(path); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	if os.PathSeparator == '\\' {
		t.Skip("symlink permissions are platform dependent on Windows")
	}
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "link.txt")); err != nil {
		t.Fatal(err)
	}
	c := New(Config{}).WithContext(t.Context())
	if _, err := c.zipSigningInputs(directory); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("directory symlink accepted: %v", err)
	}
}

func TestZIPDirectoryMetadataBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		payload   []byte
		wantError bool
	}{
		{"unsigned.txt", []byte("unsigned payload hidden by directory attributes"), true},
		{"empty.txt", nil, true},
		{"valid/", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var encoded bytes.Buffer
			writer := zip.NewWriter(&encoded)
			header := &zip.FileHeader{Name: tc.name, Method: zip.Store}
			header.SetMode(os.ModeDir | 0o755)
			file, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(tc.payload); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "directory.zip")
			if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			c := New(Config{}).WithContext(t.Context())
			_, err = c.zipEntries(path)
			if (err != nil) != tc.wantError {
				t.Fatalf("directory metadata accepted=%t, want error=%t: %v", err == nil, tc.wantError, err)
			}
		})
	}
}

func TestNCAManifestRejectsAmbiguousXML(t *testing.T) {
	const signature = "META-INF/signature-test.cms"
	const valid = `<NCAManifest><SigReference URI="` + signature + `"/><DataObjectReference URI="data.txt"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AA==</DigestValue></DataObjectReference></NCAManifest>`
	entries := map[string][]byte{zipManifestPath: []byte(valid), signature: {1}, "data.txt": {1}}
	if _, err := parseNCAManifest(entries); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"namespaced signature", `<SigReference `, `<other:SigReference xmlns:other="urn:other" `},
		{"duplicate URI", `URI="` + signature + `"`, `URI="META-INF/signature-other.cms" URI="` + signature + `"`},
		{"duplicate digest method", `<DigestMethod `, `<DigestMethod Algorithm="unknown"/><DigestMethod `},
		{"duplicate digest value", `<DigestValue>`, `<DigestValue>wrong</DigestValue><DigestValue>`},
		{"unknown child", `</NCAManifest>`, `<Unknown/></NCAManifest>`},
		{"DTD", `<NCAManifest>`, `<!DOCTYPE NCAManifest><NCAManifest>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries[zipManifestPath] = []byte(strings.Replace(valid, tc.old, tc.new, 1))
			if _, err := parseNCAManifest(entries); err == nil {
				t.Fatal("ambiguous or unsupported manifest accepted")
			}
		})
	}
}

func TestZIPLocalHeaders(t *testing.T) {
	for _, method := range []uint16{zip.Store, zip.Deflate} {
		var encoded bytes.Buffer
		writer := zip.NewWriter(&encoded)
		file, err := writer.CreateHeader(&zip.FileHeader{Name: "safe.txt", Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("signed payload")); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		for _, fault := range []string{"valid", "name", "flags", "method", "CRC", "size", "prefix"} {
			t.Run(fault, func(t *testing.T) {
				data := bytes.Clone(encoded.Bytes())
				switch fault {
				case "name":
					copy(data[30:], "../a.txt")
				case "flags":
					data[6] ^= 1
				case "method":
					data[8] ^= 1
				case "CRC":
					data[14] ^= 1
				case "size":
					data[18] ^= 1
				case "prefix":
					data = append([]byte("unlisted prefix"), data...)
				}
				path := filepath.Join(t.TempDir(), "input.zip")
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				c := New(Config{}).WithContext(t.Context())
				_, err := c.zipEntries(path)
				if (err == nil) != (fault == "valid") {
					t.Fatalf("local header fault %s: %v", fault, err)
				}
			})
		}
	}
}

func TestZIP64LocalSizes(t *testing.T) {
	data := []byte("bounded ZIP64 payload")
	extra := make([]byte, 20)
	binary.LittleEndian.PutUint16(extra, 1)
	binary.LittleEndian.PutUint16(extra[2:], 16)
	binary.LittleEndian.PutUint64(extra[4:], uint64(len(data)))
	binary.LittleEndian.PutUint64(extra[12:], uint64(len(data)))
	var encoded bytes.Buffer
	writer := zip.NewWriter(&encoded)
	file, err := writer.CreateRaw(&zip.FileHeader{Name: "payload", Method: zip.Store, CRC32: crc32.ChecksumIEEE(data), CompressedSize64: uint64(len(data)), UncompressedSize64: uint64(len(data)), Extra: extra})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	// Force the local header to obtain its two sizes from the ZIP64 extra.
	valid := bytes.Clone(encoded.Bytes())
	binary.LittleEndian.PutUint32(valid[18:], 0xffffffff)
	binary.LittleEndian.PutUint32(valid[22:], 0xffffffff)
	for _, corrupt := range []bool{false, true} {
		input := bytes.Clone(valid)
		if corrupt {
			input[30+len("payload")+4] ^= 1
		}
		path := filepath.Join(t.TempDir(), "zip64.zip")
		if err := os.WriteFile(path, input, 0o600); err != nil {
			t.Fatal(err)
		}
		c := New(Config{}).WithContext(t.Context())
		entries, err := c.zipEntries(path)
		if corrupt {
			if err == nil {
				t.Fatal("inconsistent ZIP64 local size accepted")
			}
		} else if err != nil || !bytes.Equal(entries["payload"], data) {
			t.Fatalf("bounded ZIP64 rejected: %v", err)
		}
	}
}
