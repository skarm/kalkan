package javakalkan

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
)

func (c *Operation) readFile(path string) ([]byte, error) {
	// The pipe protocol and Java arrays use signed 32-bit lengths. Reject an
	// oversized file before buffering it, even without a caller-specified cap.
	limit := int64(math.MaxInt32)
	if c.cfg.MaxInputSize > 0 {
		limit = min(limit, c.cfg.MaxInputSize)
	}

	return c.readRegularFile(path, limit)
}

func (c *Operation) readEvidenceFile(path string) ([]byte, error) {
	return c.readRegularFile(path, c.evidenceLimit())
}

func (c *Operation) readRegularFile(path string, limit int64) ([]byte, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	// Check before Open to reject devices/pipes without waiting for a peer.
	// Callers must keep file paths and contents unchanged during an operation.
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: Java input file must be regular", ErrInvalidInput)
	}

	if info.Size() > limit {
		return nil, fmt.Errorf("%w: file exceeds maximum input size", ErrInvalidInput)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err = f.Stat()
	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: Java input file must be regular", ErrInvalidInput)
	}

	return c.readInput(f, limit)
}

// readInput enforces the byte limit and cancellation while buffering, including
// when a file grows during the read.
func (c *Operation) readInput(input io.Reader, limit int64) ([]byte, error) {
	if limit < 0 || limit > math.MaxInt32 {
		return nil, fmt.Errorf("%w: invalid input limit", ErrInvalidInput)
	}

	reader := io.LimitReader(input, limit+1)

	var buffer bytes.Buffer

	var chunk [32 * 1024]byte

	for {
		if err := c.ctx.Err(); err != nil {
			return nil, err
		}

		n, err := reader.Read(chunk[:])
		if int64(buffer.Len())+int64(n) > limit {
			return nil, fmt.Errorf("%w: file exceeds maximum input size", ErrInvalidInput)
		}

		_, _ = buffer.Write(chunk[:n])
		if err == io.EOF {
			return buffer.Bytes(), c.ctx.Err()
		}

		if err != nil {
			return nil, err
		}
	}
}
