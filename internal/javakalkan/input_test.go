package javakalkan

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPEMInputRequiresExactlyOneBlock(t *testing.T) {
	want := []byte("payload")
	valid := pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: want})
	for _, data := range [][]byte{valid, append([]byte(" \n\t"), valid...)} {
		got, err := decodeSinglePEM(data)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("single PEM block = %q, %v", got, err)
		}
	}
	for _, data := range [][]byte{
		append([]byte("junk\n"), valid...),
		append([]byte("-----BEGIN CMS-----\ninvalid*\n-----END CMS-----\n"), valid...),
		bytes.Repeat(valid, 2),
		append(bytes.Clone(valid), []byte("trailing junk")...),
	} {
		if got, err := decodeSinglePEM(data); !errors.Is(err, ErrInvalidInput) || got != nil {
			t.Errorf("ambiguous PEM decoded as %q, %v", got, err)
		}
	}
}

type cancelingInput struct {
	cancel context.CancelFunc
	reads  int
}

func (r *cancelingInput) Read(p []byte) (int, error) {
	r.reads++
	r.cancel()
	copy(p, "partial data")
	return len("partial data"), nil
}

func TestSharedInputLimitsAndCancellation(t *testing.T) {
	c := New(Config{}).WithContext(t.Context())
	for _, size := range []int{0, 32, 33} {
		data, err := c.readInput(bytes.NewReader(bytes.Repeat([]byte{1}, size)), 32)
		if size > 32 {
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("oversize error=%v", err)
			}
		} else if err != nil || len(data) != size {
			t.Fatalf("size=%d got=%d error=%v", size, len(data), err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c = c.WithContext(ctx)
	source := &cancelingInput{cancel: cancel}
	if data, err := c.readInput(source, 1024); !errors.Is(err, context.Canceled) || data != nil || source.reads != 1 {
		t.Fatalf("partial input escaped cancellation: data=%q err=%v reads=%d", data, err, source.reads)
	}
}

func TestFileInputBoundsBeforeBuffering(t *testing.T) {
	c := New(Config{MaxInputSize: 32}).WithContext(t.Context())
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, 33), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, read := range []func(string) ([]byte, error){c.readFile, c.readEvidenceFile} {
		if _, err := read(path); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("file bound=%v", err)
		}
	}
	if _, err := c.readRegularFile(filepath.Dir(path), 32); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("directory input=%v", err)
	}
	if _, err := c.readInput(io.LimitReader(bytes.NewReader(nil), 0), -1); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid bound=%v", err)
	}
}
