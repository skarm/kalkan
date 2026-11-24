package kalkan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/skarm/kalkan/ckalkan"
)

func cmsAppendData(ctx context.Context, data []byte, flags ckalkan.Flag, limit int64) ([]byte, ckalkan.Flag, error) {
	// Native append shares KC_IN_* flags between the existing CMS and payload.
	// Decode encoded payloads so both inputs use DER flags.
	if flags&(ckalkan.InPEM|ckalkan.InBase64) == 0 {
		return data, flags | ckalkan.InDER, nil
	}

	if flags&ckalkan.InFile != 0 {
		var err error

		data, err = readCMSInputFile(ctx, string(data), limit, true)
		if err != nil {
			return nil, 0, err
		}
	}

	if flags&ckalkan.InBase64 != 0 {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, 0, fmt.Errorf("%w: CMS append payload base64: %w", ErrInvalidInput, err)
		}

		data = decoded
	} else {
		data = bytes.TrimSpace(data)

		block, rest := pem.Decode(data)
		// pem.Decode can skip a malformed first block and return a later one.
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) || bytes.Contains(data, []byte("\n-----BEGIN ")) || block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return nil, 0, fmt.Errorf("%w: CMS append payload must contain a single PEM block", ErrInvalidInput)
		}

		data = block.Bytes
	}

	return data, flags&^(ckalkan.InBase64|ckalkan.InPEM|ckalkan.InFile) | ckalkan.InDER, nil
}

func existingCMSInput(source Source, limit int64) ([]byte, error) {
	if source.isZero() {
		return nil, nil
	}

	if source.file {
		return nil, fmt.Errorf("%w: existing CMS must be in memory", ErrInvalidInput)
	}

	data, flags, err := cmsSignatureInput(source, EncodingDER, limit)
	if err != nil {
		return nil, err
	}

	switch {
	case flags&ckalkan.InBase64 != 0:
		data, err = base64.StdEncoding.DecodeString(string(data))
	case flags&ckalkan.InPEM != 0:
		data = bytes.TrimSpace(data)

		var (
			block *pem.Block
			rest  []byte
		)

		block, rest = pem.Decode(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) || bytes.Contains(data, []byte("\n-----BEGIN ")) || block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%w: existing CMS PEM", ErrInvalidInput)
		}

		data = block.Bytes
	}

	if err != nil {
		return nil, fmt.Errorf("%w: existing CMS: %w", ErrInvalidInput, err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("%w: existing CMS is empty", ErrInvalidInput)
	}

	return data, nil
}

func cmsSignatureInput(source Source, fallback Encoding, maxInputSize int64) ([]byte, ckalkan.Flag, error) {
	if source.isZero() {
		return nil, 0, fmt.Errorf("%w: CMS signature is required", ErrInvalidInput)
	}

	if err := validateMemorySourceSize(source, "CMS signature", maxInputSize); err != nil {
		return nil, 0, err
	}

	value, err := source.bytesOrPath()
	if err != nil {
		return nil, 0, err
	}

	if !source.file && len(value) == 0 {
		return nil, 0, fmt.Errorf("%w: CMS signature is empty", ErrInvalidInput)
	}

	encoding := effectiveEncoding(source, fallback)
	switch encoding {
	case EncodingAuto, EncodingRaw, EncodingDER:
		return value, ckalkan.InDER, nil
	case EncodingBase64:
		return value, ckalkan.InBase64, nil
	case EncodingPEM:
		return value, ckalkan.InPEM, nil
	default:
		return nil, 0, fmt.Errorf("%w: unknown CMS signature encoding %d", ErrInvalidInput, encoding)
	}
}

func cmsDataInput(source Source, maxInputSize int64) ([]byte, ckalkan.Flag, error) {
	if source.isZero() {
		return nil, 0, nil
	}

	if err := validateMemorySourceSize(source, "detached CMS data", maxInputSize); err != nil {
		return nil, 0, err
	}

	value, err := source.bytesOrPath()
	if err != nil {
		return nil, 0, err
	}

	encoding := effectiveEncoding(source, EncodingRaw)
	switch encoding {
	case EncodingPEM, EncodingDER:
		return nil, 0, fmt.Errorf("%w: detached CMS data encoding %s is not supported by KalkanCrypt; use raw or base64 data", ErrInvalidInput, encodingName(encoding))
	}

	if source.file {
		if encoding == EncodingBase64 {
			return value, ckalkan.In2Base64, nil
		}

		return value, 0, nil
	}

	switch encoding {
	case EncodingAuto, EncodingRaw:
		return value, 0, nil
	case EncodingBase64:
		return value, ckalkan.In2Base64, nil
	default:
		return nil, 0, fmt.Errorf("%w: unknown CMS data encoding %d", ErrInvalidInput, encoding)
	}
}

// readCMSInputFile checks cancellation between reads and bounds actual bytes,
// including files whose reported size is unavailable. Encoded append payloads
// require regular files; certificate extraction also accepts streams.
func readCMSInputFile(ctx context.Context, path string, maxSize int64, regularOnly bool) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if regularOnly {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("kalkan: stat CMS file: %w", err)
		}

		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: CMS append payload must be a regular file", ErrInvalidInput)
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("kalkan: open CMS file: %w", err)
	}
	defer file.Close()

	info, statErr := file.Stat()
	if regularOnly {
		if statErr != nil {
			return nil, fmt.Errorf("kalkan: stat CMS file: %w", statErr)
		}

		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: CMS append payload must be a regular file", ErrInvalidInput)
		}
	}

	var buffer bytes.Buffer

	if statErr == nil && info.Mode().IsRegular() && info.Size() >= 0 {
		initial := info.Size()
		if maxSize > 0 && maxSize < math.MaxInt64 {
			initial = min(initial, maxSize+1)
		}

		if initial <= int64(math.MaxInt)-bytes.MinRead {
			buffer.Grow(int(initial) + bytes.MinRead)
		}
	}

	var reader io.Reader = file
	if maxSize > 0 && maxSize < math.MaxInt64 {
		reader = io.LimitReader(file, maxSize+1)
	}

	chunk := make([]byte, 32<<10)

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		count, readErr := reader.Read(chunk)

		_, _ = buffer.Write(chunk[:count])
		if err := validateBytesSize(buffer.Bytes(), "CMS input", maxSize); err != nil {
			return nil, err
		}

		if errors.Is(readErr, io.EOF) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			return buffer.Bytes(), nil
		}

		if readErr != nil {
			return nil, fmt.Errorf("kalkan: read CMS file: %w", readErr)
		}
	}
}
