package kalkan

import "fmt"

// Encoding describes how bytes or file contents are encoded before KalkanCrypt
// reads them.
type Encoding int

const (
	// EncodingAuto lets the operation choose the field-specific default.
	// For example, VerifyCMS treats raw CMS bytes as DER CMS input.
	EncodingAuto Encoding = iota
	// EncodingRaw means the source is plain binary/text data. Operations may
	// map raw data to the native flag that represents their raw format, such as
	// DER for CMS signatures.
	EncodingRaw
	// EncodingBase64 means the source is already base64 text.
	EncodingBase64
	// EncodingPEM means the source is PEM text.
	EncodingPEM
	// EncodingDER means the source is DER binary data.
	EncodingDER
)

// Source is an operation input that can be either in-memory bytes or a file
// path. File sources allow KalkanCrypt to read large detached payloads directly
// when the native function supports KC_IN_FILE. The zero-value Source means
// "not provided"; constructor-created empty byte sources represent explicit
// empty input and are validated by each operation's own rules.
type Source struct {
	data     []byte
	path     string
	file     bool
	encoding Encoding
	set      bool
}

// Bytes returns an in-memory raw source. Use File for large payloads that
// KalkanCrypt should read directly.
func Bytes(data []byte) Source {
	return Source{data: data, encoding: EncodingRaw, set: true}
}

// Base64 returns an in-memory source that already contains base64 text.
func Base64(data []byte) Source {
	return Source{data: data, encoding: EncodingBase64, set: true}
}

// PEM returns an in-memory PEM source.
func PEM(data []byte) Source {
	return Source{data: data, encoding: EncodingPEM, set: true}
}

// DER returns an in-memory DER source.
func DER(data []byte) Source {
	return Source{data: data, encoding: EncodingDER, set: true}
}

// File returns a file-path source. Empty paths and embedded NUL bytes are
// rejected by operations before native calls.
func File(path string) Source {
	return Source{path: path, file: true, encoding: EncodingAuto, set: true}
}

// WithEncoding returns a copy of the source with an explicit encoding.
func (s Source) WithEncoding(encoding Encoding) Source {
	s.encoding = encoding
	return s
}

func (s Source) isZero() bool {
	return !s.set
}

func (s Source) isSet() bool {
	return s.set
}

func (s Source) bytesOrPath() ([]byte, error) {
	if s.file {
		path, err := validateNativePathString("file source path", s.path)
		if err != nil {
			return nil, err
		}

		return []byte(path), nil
	}

	return s.data, nil
}

func effectiveEncoding(source Source, fallback Encoding) Encoding {
	if source.encoding != EncodingAuto {
		return source.encoding
	}

	if fallback != EncodingAuto {
		return fallback
	}

	return EncodingRaw
}

func validateEncoding(encoding Encoding) error {
	switch encoding {
	case EncodingAuto, EncodingRaw, EncodingBase64, EncodingPEM, EncodingDER:
		return nil
	default:
		return fmt.Errorf("%w: unknown encoding %d", ErrInvalidInput, encoding)
	}
}
