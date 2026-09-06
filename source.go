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
// A source encoding other than EncodingAuto takes precedence over request
// encoding fields and operation defaults. Byte constructors set an explicit
// encoding; File starts with EncodingAuto.
type Source struct {
	path     string
	data     []byte
	encoding Encoding
	file     bool
	set      bool
}

// SourceDescriptor describes an input without changing its presence, encoding,
// or source kind. Data is borrowed from Source; it is not copied.
type SourceDescriptor struct {
	// Path is the native file path when File is true.
	Path string
	// Data contains the in-memory input when File is false. It aliases the
	// source bytes; callers must not modify it while an operation uses them.
	Data []byte
	// Encoding describes the input format. EncodingAuto uses the request or
	// operation default.
	Encoding Encoding
	// File reports whether the source refers to Path rather than Data.
	File bool
	// Set distinguishes a provided source, including empty data, from an
	// absent source. Fields other than Set do not establish presence.
	Set bool
}

// Describe returns the source's fields for explicit transport or inspection.
// Its Data aliases the source bytes and must not be changed while an operation
// uses the source. An absent Source differs from a present empty byte source.
func (s Source) Describe() SourceDescriptor {
	return SourceDescriptor{
		Data: s.data, Path: s.path, File: s.file, Encoding: s.encoding, Set: s.set,
	}
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

// WithEncoding returns a copy of the source with the chosen encoding.
// EncodingAuto restores the request or operation fallback.
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
