package kalkan

import (
	"bytes"
	"encoding/pem"
	"fmt"
)

// parseCertificatePEM accepts exactly one nonempty CERTIFICATE block. Unlike
// pem.Decode, it must not skip a malformed first block and select a later one.
func parseCertificatePEM(data []byte) ([]byte, error) {
	data = bytes.TrimSpace(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		if block, _ := pem.Decode(data); block != nil {
			return nil, fmt.Errorf("%w: certificate PEM contains leading data", ErrInvalidInput)
		}

		return nil, fmt.Errorf("%w: certificate contains invalid PEM", ErrInvalidInput)
	}

	first := data
	if next := bytes.Index(data, []byte("\n-----BEGIN ")); next >= 0 {
		first = data[:next]
	}

	block, rest := pem.Decode(first)
	if block == nil {
		return nil, fmt.Errorf("%w: certificate contains invalid PEM", ErrInvalidInput)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: certificate PEM block type must be CERTIFICATE, got %q", ErrInvalidInput, block.Type)
	}

	// Restore the complete remainder, including any later BEGIN delimiter
	// excluded from the decoder's view of the first block.
	rest = bytes.TrimSpace(data[len(first)-len(rest):])
	if len(rest) != 0 {
		if next, _ := pem.Decode(rest); next != nil {
			return nil, fmt.Errorf("%w: certificate PEM contains multiple PEM blocks", ErrInvalidInput)
		}

		return nil, fmt.Errorf("%w: certificate PEM contains trailing data", ErrInvalidInput)
	}

	if len(block.Bytes) == 0 {
		return nil, fmt.Errorf("%w: certificate PEM input decodes to empty DER", ErrInvalidInput)
	}

	return block.Bytes, nil
}
