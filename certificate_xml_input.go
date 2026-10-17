package kalkan

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// xmlCertificateInput removes ambiguous signature selectors from an extraction-
// only copy. SDK 2.0.13 matches either a signature's one-based position or Id,
// whichever it encounters first. Id="2" on the first of two signatures would
// therefore make lookups 1 and 2 return that first certificate twice.
// No verification uses this copy: every byte outside unqualified ds:Signature
// Id attributes, including namespace declarations and the encoding, is retained.
func xmlCertificateInput(document []byte) []byte {
	view, sourceOffset := xmlCertificateScanView(document)

	decoder := xml.NewDecoder(bytes.NewReader(view))
	decoder.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	// Unknown entities and DTD processing remain the SDK's responsibility.
	// This decoder only locates tags; it does not validate signed XML.
	decoder.Strict = false

	var out []byte

	keptFrom := 0

	for {
		start := decoder.InputOffset()

		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			// Keep native error behavior for input this scanner cannot read.
			return document
		}

		element, ok := token.(xml.StartElement)
		if !ok || element.Name.Space != xmlnsDSig || element.Name.Local != "Signature" {
			continue
		}

		if validateUniqueXMLAttributes(element) != nil {
			return document
		}

		for _, attribute := range element.Attr {
			if attribute.Name.Space != "" || attribute.Name.Local != "Id" {
				continue
			}

			from, until := xmlSignatureIDAttribute(view[start:decoder.InputOffset()])
			if until == 0 {
				continue
			}

			attributeStart := sourceOffset(start + int64(from))
			attributeEnd := sourceOffset(start + int64(until))

			out = append(out, document[keptFrom:attributeStart]...)
			keptFrom = attributeEnd

			break
		}
	}

	if out == nil {
		return document
	}

	return append(out, document[keptFrom:]...)
}

// xmlCertificateScanView makes ASCII-compatible legacy XML readable by the
// scanner without merging distinct names. Each non-ASCII byte maps to a unique
// three-byte CJK rune, valid in XML names. Only the scan view changes; the
// monotonic offset mapper locates the corresponding bytes in the original.
func xmlCertificateScanView(document []byte) ([]byte, func(int64) int) {
	if len(document) >= 2 {
		switch {
		case bytes.HasPrefix(document, []byte{0xff, 0xfe}), document[0] == '<' && document[1] == 0:
			return xmlUTF16CertificateScanView(document, binary.LittleEndian)
		case bytes.HasPrefix(document, []byte{0xfe, 0xff}), document[0] == 0 && document[1] == '<':
			return xmlUTF16CertificateScanView(document, binary.BigEndian)
		}
	}

	if utf8.Valid(document) {
		return document, func(offset int64) int { return int(offset) }
	}

	view := make([]byte, 0, len(document))
	for _, value := range document {
		if value < utf8.RuneSelf {
			view = append(view, value)
		} else {
			view = utf8.AppendRune(view, 0x4E00+rune(value))
		}
	}

	scanned, consumed := 0, 0

	return view, func(offset int64) int {
		for scanned < int(offset) {
			scanned++
			if document[consumed] >= utf8.RuneSelf {
				scanned += 2
			}

			consumed++
		}

		return consumed
	}
}

// xmlUTF16CertificateScanView decodes only the scanner's view. The mapper
// accounts for surrogate pairs so edits still use the original UTF-16 bytes,
// including the BOM, declaration, and all non-Id attributes and text.
func xmlUTF16CertificateScanView(document []byte, order binary.ByteOrder) ([]byte, func(int64) int) {
	unchanged := func(offset int64) int { return int(offset) }
	if len(document)%2 != 0 {
		return document, unchanged
	}

	view := make([]byte, 0, len(document))
	for index := 0; index < len(document); index += 2 {
		value := rune(order.Uint16(document[index:]))
		if utf16.IsSurrogate(value) {
			if index+4 > len(document) {
				return document, unchanged
			}

			value = utf16.DecodeRune(value, rune(order.Uint16(document[index+2:])))
			if value == utf8.RuneError {
				return document, unchanged
			}

			index += 2
		}

		view = utf8.AppendRune(view, value)
	}

	scanned, consumed := 0, 0

	return view, func(offset int64) int {
		for scanned < int(offset) {
			value, size := utf8.DecodeRune(view[scanned:])
			scanned += size

			consumed += 2
			if value > 0xffff {
				consumed += 2
			}
		}

		return consumed
	}
}

// xmlSignatureIDAttribute finds the original byte span of an unqualified Id
// attribute in a start tag already recognized by encoding/xml. Quoted values
// are skipped as units so text such as `title="Id='2' >"` cannot be changed.
func xmlSignatureIDAttribute(tag []byte) (int, int) {
	i := 1 // Skip '<' and the element name.
	for i < len(tag) && !xmlTagWhitespace(tag[i]) && tag[i] != '>' && tag[i] != '/' {
		i++
	}

	for i < len(tag) {
		for i < len(tag) && xmlTagWhitespace(tag[i]) {
			i++
		}

		start := i
		for i < len(tag) && !xmlTagWhitespace(tag[i]) && tag[i] != '=' && tag[i] != '>' && tag[i] != '/' {
			i++
		}

		name := tag[start:i]
		for i < len(tag) && xmlTagWhitespace(tag[i]) {
			i++
		}

		if i >= len(tag) || tag[i] != '=' {
			return 0, 0
		}

		i++
		for i < len(tag) && xmlTagWhitespace(tag[i]) {
			i++
		}

		if i >= len(tag) || tag[i] != '\'' && tag[i] != '"' {
			return 0, 0
		}

		quote := tag[i]

		i++
		for i < len(tag) && tag[i] != quote {
			i++
		}

		if i >= len(tag) {
			return 0, 0
		}

		i++
		if bytes.Equal(name, []byte("Id")) {
			return start, i
		}
	}

	return 0, 0
}

func xmlTagWhitespace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}
