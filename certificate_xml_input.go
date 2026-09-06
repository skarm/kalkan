package kalkan

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
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
		start := sourceOffset(decoder.InputOffset())

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

		for _, attribute := range element.Attr {
			if attribute.Name.Space != "" || attribute.Name.Local != "Id" {
				continue
			}

			end := sourceOffset(decoder.InputOffset())

			from, until := xmlSignatureIDAttribute(document[start:end])
			if until == 0 {
				continue
			}

			out = append(out, document[keptFrom:start+from]...)
			keptFrom = start + until

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
