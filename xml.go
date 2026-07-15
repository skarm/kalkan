package kalkan

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/kalkan/ckalkan"
)

const (
	xmlnsSOAP   = "http://schemas.xmlsoap.org/soap/envelope/"
	xmlnsSOAP12 = "http://www.w3.org/2003/05/soap-envelope"
	xmlnsWSU    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	xmlnsDSig   = "http://www.w3.org/2000/09/xmldsig#"
	xmlnsXML    = "http://www.w3.org/XML/1998/namespace"
)

// XMLCanonicalization selects the XML canonicalization algorithm passed to
// KalkanCrypt. The zero value selects XMLCanonicalizationInclusive.
type XMLCanonicalization int

const (
	// XMLCanonicalizationInclusive selects inclusive XML canonicalization.
	XMLCanonicalizationInclusive XMLCanonicalization = iota
	// XMLCanonicalizationInclusiveWithComments selects inclusive XML
	// canonicalization and preserves comments.
	XMLCanonicalizationInclusiveWithComments
	// XMLCanonicalizationInclusive11 selects inclusive XML canonicalization 1.1.
	XMLCanonicalizationInclusive11
	// XMLCanonicalizationInclusive11WithComments selects inclusive XML
	// canonicalization 1.1 and preserves comments.
	XMLCanonicalizationInclusive11WithComments
	// XMLCanonicalizationExclusive selects exclusive XML canonicalization.
	XMLCanonicalizationExclusive
	// XMLCanonicalizationExclusiveWithComments selects exclusive XML
	// canonicalization and preserves comments.
	XMLCanonicalizationExclusiveWithComments
)

// SignXMLRequest describes XML signing input.
type SignXMLRequest struct {
	// Alias selects a loaded key alias.
	Alias string
	// XML is the XML document to sign.
	XML Source
	// SignNodeID is the XML node id passed to KalkanCrypt.
	SignNodeID string
	// ParentSignNode is the parent signature node name passed to KalkanCrypt.
	ParentSignNode string
	// ParentNamespace is the parent signature namespace passed to KalkanCrypt.
	ParentNamespace string
	// Canonicalization selects the XML canonicalization algorithm.
	Canonicalization XMLCanonicalization
	// CertificateTimeCheck controls certificate-time validation.
	CertificateTimeCheck CertificateTimeCheck
}

// VerifyXMLRequest describes XML verification input.
type VerifyXMLRequest struct {
	// Alias is forwarded to KalkanCrypt's VerifyXML alias parameter.
	Alias string
	// XML is the signed XML document to verify.
	XML Source
	// ExpectedBodyID binds verification to a SOAP Body wsu:Id. It is required for
	// SOAP 1.1 and SOAP 1.2 and must be empty for non-SOAP XML.
	ExpectedBodyID string
	// Canonicalization selects the XML canonicalization algorithm.
	Canonicalization XMLCanonicalization
	// CertificateTimeCheck controls certificate-time validation.
	CertificateTimeCheck CertificateTimeCheck
}

// SignWSSERequest describes WS-Security XML signing input.
type SignWSSERequest struct {
	// Alias selects a loaded key alias.
	Alias string
	// XML is either a full SOAP envelope or a payload that should be wrapped when
	// WrapSOAP is true.
	XML Source
	// BodyID is the wsu:Id value of the SOAP Body that KalkanCrypt signs. It
	// is required whether XML is wrapped by this package or supplied as a full
	// SOAP envelope.
	BodyID string
	// WrapSOAP wraps XML into a minimal SOAP envelope before signing.
	WrapSOAP bool
	// Canonicalization selects the XML canonicalization algorithm.
	Canonicalization XMLCanonicalization
	// CertificateTimeCheck controls certificate-time validation.
	CertificateTimeCheck CertificateTimeCheck
}

// SignedXML is returned by SignXML and SignWSSE.
type SignedXML struct {
	// XML contains the signed XML document.
	XML []byte
}

// SignXML signs an XML document.
func (c *Client) SignXML(ctx context.Context, req SignXMLRequest) (*SignedXML, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	input, err := xmlInput(req.XML, c.configuredMaxInputSize())
	if err != nil {
		return nil, err
	}

	flags, err := xmlCanonicalizationFlag(req.Canonicalization)
	if err != nil {
		return nil, err
	}

	checkFlags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	flags |= checkFlags

	out, err := withLockedLibraryResult(c, ctx, "SignXML", func(native xmlSignatures) ([]byte, error) {
		return native.SignXML(ckalkan.SignXMLRequest{
			Alias:           req.Alias,
			Flags:           flags,
			XML:             input,
			SignNodeID:      req.SignNodeID,
			ParentSignNode:  req.ParentSignNode,
			ParentNamespace: req.ParentNamespace,
		})
	})
	if err != nil {
		return nil, err
	}

	return &SignedXML{XML: out}, nil
}

// VerifyXML verifies a signed XML document.
func (c *Client) VerifyXML(ctx context.Context, req VerifyXMLRequest) (*Verification, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	input, err := xmlInput(req.XML, c.configuredMaxInputSize())
	if err != nil {
		return nil, err
	}

	flags, err := xmlCanonicalizationFlag(req.Canonicalization)
	if err != nil {
		return nil, err
	}

	checkFlags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	flags |= checkFlags

	if err := validateXMLVerificationStructure(input, req.ExpectedBodyID); err != nil {
		return nil, err
	}

	info, err := withLockedLibraryResult(c, ctx, "VerifyXML", func(native xmlSignatures) (string, error) {
		return native.VerifyXML(req.Alias, flags, input)
	})
	if err != nil {
		return nil, err
	}

	return &Verification{Info: info}, nil
}

// SignWSSE signs a SOAP/WS-Security document.
func (c *Client) SignWSSE(ctx context.Context, req SignWSSERequest) (*SignedXML, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	input, err := xmlInput(req.XML, c.configuredMaxInputSize())
	if err != nil {
		return nil, err
	}

	bodyID := req.BodyID
	if err := validateSOAPBodyID(bodyID); err != nil {
		return nil, err
	}

	if req.WrapSOAP {
		input, err = wrapSOAPBody(input, bodyID)
		if err != nil {
			return nil, err
		}

		if err := validateBytesSize(input, "WSSE XML input", c.configuredMaxInputSize()); err != nil {
			return nil, err
		}
	}

	flags, err := xmlCanonicalizationFlag(req.Canonicalization)
	if err != nil {
		return nil, err
	}

	checkFlags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	flags |= checkFlags

	out, err := withLockedLibraryResult(c, ctx, "SignWSSE", func(native xmlSignatures) ([]byte, error) {
		return native.SignWSSE(ckalkan.SignWSSERequest{
			Alias:      req.Alias,
			Flags:      flags,
			XML:        input,
			SignNodeID: bodyID,
		})
	})
	if err != nil {
		return nil, err
	}

	return &SignedXML{XML: out}, nil
}

func wrapSOAPBody(payload []byte, id string) ([]byte, error) {
	if err := validateSOAPBodyID(id); err != nil {
		return nil, err
	}

	if err := validateSingleXMLElement(payload); err != nil {
		return nil, err
	}

	var out bytes.Buffer

	encoder := xml.NewEncoder(&out)

	envelope := xml.StartElement{
		Name: xml.Name{Local: "soap:Envelope"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns:soap"}, Value: xmlnsSOAP},
			{Name: xml.Name{Local: "xmlns:wsu"}, Value: xmlnsWSU},
		},
	}
	body := xml.StartElement{
		Name: xml.Name{Local: "soap:Body"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "wsu:Id"}, Value: id},
		},
	}

	if err := encoder.EncodeToken(envelope); err != nil {
		return nil, err
	}

	if err := encoder.EncodeToken(body); err != nil {
		return nil, err
	}

	if err := encoder.Flush(); err != nil {
		return nil, err
	}

	if _, err := out.Write(payload); err != nil {
		return nil, err
	}

	if err := encoder.EncodeToken(body.End()); err != nil {
		return nil, err
	}

	if err := encoder.EncodeToken(envelope.End()); err != nil {
		return nil, err
	}

	if err := encoder.Flush(); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func validateSOAPBodyID(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return fmt.Errorf("%w: SOAP BodyID is required", ErrInvalidInput)
	}

	if id != trimmed {
		return fmt.Errorf("%w: SOAP BodyID must be a valid XML ID/NCName", ErrInvalidInput)
	}

	if !isXMLNCName(id) {
		return fmt.Errorf("%w: SOAP BodyID must be a valid XML ID/NCName", ErrInvalidInput)
	}

	return nil
}

func isXMLNCName(value string) bool {
	if value == "" {
		return false
	}

	first, size := utf8.DecodeRuneInString(value)
	if first == utf8.RuneError && size == 1 {
		return false
	}

	if !isXMLNameStart(first) {
		return false
	}

	for _, r := range value[size:] {
		if r == utf8.RuneError || !isXMLNameChar(r) {
			return false
		}
	}

	return true
}

func isXMLNameStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}

func isXMLNameChar(r rune) bool {
	return isXMLNameStart(r) || unicode.IsDigit(r) || r == '-' || r == '.'
}

func validateSingleXMLElement(payload []byte) error {
	if len(bytes.TrimSpace(payload)) == 0 {
		return fmt.Errorf("%w: SOAP payload is empty", ErrInvalidInput)
	}

	decoder := xml.NewDecoder(bytes.NewReader(payload))

	var (
		roots int
		depth int
	)

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("%w: SOAP payload must be a well-formed XML element: %w", ErrInvalidInput, err)
		}

		switch value := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
				if roots > 1 {
					return fmt.Errorf("%w: SOAP payload must be a single XML element", ErrInvalidInput)
				}
			}

			depth++
		case xml.EndElement:
			if depth == 0 {
				return fmt.Errorf("%w: SOAP payload must be a well-formed XML element", ErrInvalidInput)
			}

			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(value)) > 0 {
				if roots == 0 {
					return fmt.Errorf("%w: SOAP payload must be a single XML element", ErrInvalidInput)
				}

				return fmt.Errorf("%w: SOAP payload must not contain trailing text", ErrInvalidInput)
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
			if depth == 0 {
				return fmt.Errorf("%w: SOAP payload must be a single XML element", ErrInvalidInput)
			}
		}
	}

	if roots != 1 || depth != 0 {
		return fmt.Errorf("%w: SOAP payload must be a single XML element", ErrInvalidInput)
	}

	return nil
}

type signedSOAPBodyReference struct {
	documentElementCount   int
	root                   xml.Name
	soapBodyCount          int
	directSOAPBodyCount    int
	expectedBodyCount      int
	expectedIDCount        int
	signatureCount         int
	signedInfoCount        int
	directSignedInfoCount  int
	expectedReferenceCount int
}

func validateXMLVerificationStructure(document []byte, expectedID string) error {
	if expectedID != "" {
		if err := validateSOAPBodyID(expectedID); err != nil {
			return err
		}
	}

	root, err := xmlDocumentRoot(document)
	if err != nil {
		return err
	}

	if !isSOAPEnvelope(root) {
		if expectedID != "" {
			return fmt.Errorf("%w: ExpectedBodyID requires a SOAP 1.1 or SOAP 1.2 Envelope", ErrInvalidInput)
		}

		// Non-SOAP XML retains native verification semantics.
		return nil
	}

	if expectedID == "" {
		return fmt.Errorf("%w: ExpectedBodyID is required for SOAP verification", ErrInvalidInput)
	}

	binding, err := collectSignedSOAPBodyReference(document, expectedID)
	if err != nil {
		return err
	}

	if binding.documentElementCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one document element, got %d", ErrInvalidInput, binding.documentElementCount)
	}

	if binding.signatureCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one ds:Signature, got %d", ErrInvalidInput, binding.signatureCount)
	}

	if binding.signedInfoCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one ds:SignedInfo, got %d", ErrInvalidInput, binding.signedInfoCount)
	}

	if binding.directSignedInfoCount != 1 {
		return fmt.Errorf("%w: the ds:SignedInfo must be a direct child of ds:Signature", ErrInvalidInput)
	}

	if binding.soapBodyCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one SOAP Body, got %d", ErrInvalidInput, binding.soapBodyCount)
	}

	if binding.directSOAPBodyCount != 1 {
		return fmt.Errorf("%w: signed XML SOAP Body must be the direct child of the SOAP Envelope", ErrInvalidInput)
	}

	if binding.expectedIDCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one XML ID with value %q, got %d", ErrInvalidInput, expectedID, binding.expectedIDCount)
	}

	if binding.expectedBodyCount != 1 {
		return fmt.Errorf("%w: signed XML SOAP Body must have wsu:Id %q", ErrInvalidInput, expectedID)
	}

	if binding.expectedReferenceCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one direct ds:Reference URI=\"#%s\", got %d", ErrInvalidInput, expectedID, binding.expectedReferenceCount)
	}

	return nil
}

func xmlDocumentRoot(document []byte) (xml.Name, error) {
	decoder := xml.NewDecoder(bytes.NewReader(document))
	// Treat declared ASCII-compatible encodings as byte-compatible while reading
	// an ASCII root tag.
	decoder.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return xml.Name{}, fmt.Errorf("%w: signed XML has no document element", ErrInvalidInput)
		}

		if err != nil {
			return xml.Name{}, fmt.Errorf("%w: signed XML must be well-formed: %w", ErrInvalidInput, err)
		}

		if start, ok := token.(xml.StartElement); ok {
			return start.Name, nil
		}
	}
}

func collectSignedSOAPBodyReference(document []byte, expectedID string) (signedSOAPBodyReference, error) {
	decoder := xml.NewDecoder(bytes.NewReader(document))

	var (
		binding signedSOAPBodyReference
		stack   = make([]xml.Name, 0, 16)
	)

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return signedSOAPBodyReference{}, fmt.Errorf("%w: signed XML must be well-formed: %w", ErrInvalidInput, err)
		}

		switch tok := token.(type) {
		case xml.StartElement:
			if err := validateUniqueXMLAttributes(tok); err != nil {
				return signedSOAPBodyReference{}, err
			}

			observeXMLVerificationElement(&binding, tok, expectedID, stack)
			stack = append(stack, tok.Name)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(tok)) != 0 {
				return signedSOAPBodyReference{}, fmt.Errorf("%w: signed XML must not contain text outside the document element", ErrInvalidInput)
			}
		case xml.Directive:
			return signedSOAPBodyReference{}, fmt.Errorf("%w: signed XML directives and DTDs are not allowed", ErrInvalidInput)
		default:
			continue
		}
	}

	return binding, nil
}

func observeXMLVerificationElement(binding *signedSOAPBodyReference, start xml.StartElement, expectedID string, ancestors []xml.Name) {
	depth := len(ancestors)
	if depth == 0 {
		binding.documentElementCount++
		if binding.documentElementCount == 1 {
			binding.root = start.Name
		}
	}

	binding.expectedIDCount += matchingXMLIDCount(start, expectedID)
	if isDSigSignature(start.Name) {
		binding.signatureCount++
	}

	if isDSigSignedInfo(start.Name) {
		binding.signedInfoCount++
		if depth > 0 && isDSigSignature(ancestors[depth-1]) {
			binding.directSignedInfoCount++
		}
	}

	if isDSigReference(start.Name) && depth >= 2 &&
		isDSigSignedInfo(ancestors[depth-1]) && isDSigSignature(ancestors[depth-2]) {
		if referenceURI(start) == "#"+expectedID {
			binding.expectedReferenceCount++
		}
	}

	if !isSOAPBody(start.Name) {
		return
	}

	binding.soapBodyCount++
	if len(ancestors) != 1 || !isSOAPEnvelope(binding.root) || start.Name.Space != binding.root.Space {
		return
	}

	binding.directSOAPBodyCount++
	if hasWSUID(start, expectedID) {
		binding.expectedBodyCount++
	}
}

func isSOAPEnvelope(name xml.Name) bool {
	return name.Local == "Envelope" && (name.Space == xmlnsSOAP || name.Space == xmlnsSOAP12)
}

func isSOAPBody(name xml.Name) bool {
	return name.Local == "Body" && (name.Space == xmlnsSOAP || name.Space == xmlnsSOAP12)
}

func isDSigReference(name xml.Name) bool {
	return name.Local == "Reference" && name.Space == xmlnsDSig
}

func isDSigSignature(name xml.Name) bool {
	return name.Local == "Signature" && name.Space == xmlnsDSig
}

func isDSigSignedInfo(name xml.Name) bool {
	return name.Local == "SignedInfo" && name.Space == xmlnsDSig
}

func hasWSUID(start xml.StartElement, id string) bool {
	for _, attr := range start.Attr {
		if attr.Name.Space == xmlnsWSU && attr.Name.Local == "Id" && xmlIDEquals(attr.Value, id) {
			return true
		}
	}

	return false
}

func matchingXMLIDCount(start xml.StartElement, id string) int {
	if id == "" {
		return 0
	}

	count := 0

	for _, attr := range start.Attr {
		if !xmlIDEquals(attr.Value, id) {
			continue
		}

		if attr.Name.Space == xmlnsWSU && attr.Name.Local == "Id" ||
			attr.Name.Space == xmlnsXML && attr.Name.Local == "id" ||
			attr.Name.Space == "" && (attr.Name.Local == "Id" || attr.Name.Local == "ID") {
			count++
		}
	}

	return count
}

func xmlIDEquals(value, expected string) bool {
	// ExpectedBodyID is an NCName, so ID whitespace collapse reduces to trimming
	// XML whitespace.
	return strings.Trim(value, " \t\r\n") == expected
}

func referenceURI(start xml.StartElement) string {
	for _, attr := range start.Attr {
		if attr.Name.Space == "" && attr.Name.Local == "URI" {
			return attr.Value
		}
	}

	return ""
}

func validateUniqueXMLAttributes(start xml.StartElement) error {
	seen := make(map[xml.Name]struct{}, len(start.Attr))
	for _, attr := range start.Attr {
		if _, ok := seen[attr.Name]; ok {
			return fmt.Errorf("%w: signed XML element %q contains duplicate attribute %q", ErrInvalidInput, start.Name.Local, attr.Name.Local)
		}

		seen[attr.Name] = struct{}{}
	}

	return nil
}

func xmlInput(source Source, maxInputSize int64) ([]byte, error) {
	if !source.isSet() {
		return nil, fmt.Errorf("%w: XML source is required", ErrInvalidInput)
	}

	if source.file {
		return nil, fmt.Errorf("%w: XML file sources are not supported", ErrInvalidInput)
	}

	if err := validateEncoding(source.encoding); err != nil {
		return nil, err
	}

	switch source.encoding {
	case EncodingAuto, EncodingRaw:
	default:
		return nil, fmt.Errorf("%w: XML source encoding %d is not supported", ErrInvalidInput, source.encoding)
	}

	if err := validateMemorySourceSize(source, "XML input", maxInputSize); err != nil {
		return nil, err
	}

	input, err := source.bytesOrPath()
	if err != nil {
		return nil, err
	}

	if len(bytes.TrimSpace(input)) == 0 {
		return nil, fmt.Errorf("%w: XML input is empty", ErrInvalidInput)
	}

	return input, nil
}

func xmlCanonicalizationFlag(canonicalization XMLCanonicalization) (ckalkan.Flag, error) {
	switch canonicalization {
	case XMLCanonicalizationInclusive:
		return ckalkan.XMLInclC14N, nil
	case XMLCanonicalizationInclusiveWithComments:
		return ckalkan.XMLInclC14NComment, nil
	case XMLCanonicalizationInclusive11:
		return ckalkan.XMLInclC14N11, nil
	case XMLCanonicalizationInclusive11WithComments:
		return ckalkan.XMLInclC14N11Comment, nil
	case XMLCanonicalizationExclusive:
		return ckalkan.XMLExclC14N, nil
	case XMLCanonicalizationExclusiveWithComments:
		return ckalkan.XMLExclC14NComment, nil
	default:
		return 0, fmt.Errorf("%w: unknown XML canonicalization %d", ErrInvalidInput, canonicalization)
	}
}
