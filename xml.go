package kalkan

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/skarm/kalkan/ckalkan"
)

const (
	xmlnsSOAP   = "http://schemas.xmlsoap.org/soap/envelope/"
	xmlnsSOAP12 = "http://www.w3.org/2003/05/soap-envelope"
	xmlnsWSU    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	xmlnsDSig   = "http://www.w3.org/2000/09/xmldsig#"
	xmlnsXML    = "http://www.w3.org/XML/1998/namespace"

	xmlWhitespaceChars = " \t\r\n"

	// Existing SOAP/WS-Security fixtures use only Exclusive XML Canonicalization
	// for the Body reference transform. Keep this allowlist intentionally narrow.
	xmlAlgorithmExclusiveCanonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#"

	soapEnvelopePrefix = `<soap:Envelope xmlns:soap="` + xmlnsSOAP +
		`" xmlns:wsu="` + xmlnsWSU + `"><soap:Body wsu:Id="`
	soapEnvelopeBodySuffix = `</soap:Body></soap:Envelope>`
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

	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "alias", value: req.Alias},
		{name: "XML sign node ID", value: req.SignNodeID},
		{name: "XML parent sign node", value: req.ParentSignNode},
		{name: "XML parent namespace", value: req.ParentNamespace},
	} {
		if err := rejectEmbeddedNUL(field.name, field.value); err != nil {
			return nil, err
		}
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

	if err := rejectEmbeddedNUL("alias", req.Alias); err != nil {
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

	if err := rejectEmbeddedNUL("alias", req.Alias); err != nil {
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

	logicalLen := len(soapEnvelopePrefix) + len(id) + 2 + len(payload) + len(soapEnvelopeBodySuffix)
	out := make([]byte, 0, logicalLen+1)
	out = append(out, soapEnvelopePrefix...)
	out = append(out, id...)
	out = append(out, '"', '>')
	out = append(out, payload...)
	out = append(out, soapEnvelopeBodySuffix...)
	out = append(out, 0)

	// Keep the terminator outside the logical XML. The Linux native adapter can
	// reuse this internal buffer instead of allocating and copying it again.
	return out[:logicalLen], nil
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
	if value == "" || !utf8.ValidString(value) {
		return false
	}

	first, size := utf8.DecodeRuneInString(value)
	if !isXMLNameStart(first) {
		return false
	}

	for _, r := range value[size:] {
		if !isXMLNameChar(r) {
			return false
		}
	}

	return true
}

func isXMLNameStart(r rune) bool {
	// XML 1.0 (Fifth Edition) NameStartChar ranges, excluding the colon that
	// NCName does not permit.
	return r == '_' ||
		'A' <= r && r <= 'Z' ||
		'a' <= r && r <= 'z' ||
		0xC0 <= r && r <= 0xD6 ||
		0xD8 <= r && r <= 0xF6 ||
		0xF8 <= r && r <= 0x2FF ||
		0x370 <= r && r <= 0x37D ||
		0x37F <= r && r <= 0x1FFF ||
		0x200C <= r && r <= 0x200D ||
		0x2070 <= r && r <= 0x218F ||
		0x2C00 <= r && r <= 0x2FEF ||
		0x3001 <= r && r <= 0xD7FF ||
		0xF900 <= r && r <= 0xFDCF ||
		0xFDF0 <= r && r <= 0xFFFD ||
		0x10000 <= r && r <= 0xEFFFF
}

func isXMLNameChar(r rune) bool {
	return isXMLNameStart(r) ||
		'0' <= r && r <= '9' ||
		r == '-' || r == '.' || r == 0xB7 ||
		0x300 <= r && r <= 0x36F ||
		0x203F <= r && r <= 0x2040
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

type soapVerificationState struct {
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

type soapBodyReferenceTransformState struct {
	referenceDepth           int
	transformsDepth          int
	transformsContainerCount int
	transformElementCount    int
	transformAlgorithm       string
}

type xmlDocumentPreamble struct {
	hasDirective         bool
	hasNonWhitespaceText bool
}

func validateXMLVerificationStructure(document []byte, expectedID string) error {
	if expectedID != "" {
		if err := validateSOAPBodyID(expectedID); err != nil {
			return err
		}
	}

	decoder := xml.NewDecoder(bytes.NewReader(document))

	rootElement, preamble, err := scanXMLDocumentRoot(decoder)
	if err != nil {
		// Preserve native verification semantics for non-SOAP XML with a
		// non-UTF-8 encoding declaration. SOAP input must remain valid for the
		// strict decoder used by structural verification.
		root, rootErr := xmlDocumentRoot(document)
		if rootErr != nil {
			return rootErr
		}

		isSOAP, rootErr := validateXMLVerificationRoot(root, expectedID)
		if rootErr != nil {
			return rootErr
		}

		if !isSOAP {
			return nil
		}

		return err
	}

	isSOAP, err := validateXMLVerificationRoot(rootElement.Name, expectedID)
	if err != nil {
		return err
	}

	if !isSOAP {
		return nil
	}

	if preamble.hasDirective {
		return fmt.Errorf("%w: signed XML directives and DTDs are not allowed", ErrInvalidInput)
	}

	if preamble.hasNonWhitespaceText {
		return fmt.Errorf("%w: signed XML must not contain text outside the document element", ErrInvalidInput)
	}

	state, err := collectSOAPVerificationState(decoder, rootElement, expectedID)
	if err != nil {
		return err
	}

	return validateSOAPVerificationState(state, expectedID)
}

func validateXMLVerificationRoot(root xml.Name, expectedID string) (bool, error) {
	if !isSOAPEnvelope(root) {
		if expectedID != "" {
			return false, fmt.Errorf("%w: ExpectedBodyID requires a SOAP 1.1 or SOAP 1.2 Envelope", ErrInvalidInput)
		}

		// Non-SOAP XML retains native verification semantics.
		return false, nil
	}

	if expectedID == "" {
		return true, fmt.Errorf("%w: ExpectedBodyID is required for SOAP verification", ErrInvalidInput)
	}

	return true, nil
}

func scanXMLDocumentRoot(decoder *xml.Decoder) (xml.StartElement, xmlDocumentPreamble, error) {
	var preamble xmlDocumentPreamble

	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return xml.StartElement{}, xmlDocumentPreamble{}, fmt.Errorf("%w: signed XML has no document element", ErrInvalidInput)
			}

			return xml.StartElement{}, xmlDocumentPreamble{}, fmt.Errorf("%w: signed XML must be well-formed: %w", ErrInvalidInput, err)
		}

		switch tok := token.(type) {
		case xml.StartElement:
			return tok, preamble, nil
		case xml.CharData:
			preamble.hasNonWhitespaceText = preamble.hasNonWhitespaceText || len(bytes.TrimSpace(tok)) != 0
		case xml.Directive:
			preamble.hasDirective = true
		}
	}
}

func validateSOAPVerificationState(state soapVerificationState, expectedID string) error {
	if state.documentElementCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one document element, got %d", ErrInvalidInput, state.documentElementCount)
	}

	if state.signatureCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one ds:Signature, got %d", ErrInvalidInput, state.signatureCount)
	}

	if state.signedInfoCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one ds:SignedInfo, got %d", ErrInvalidInput, state.signedInfoCount)
	}

	if state.directSignedInfoCount != 1 {
		return fmt.Errorf("%w: the ds:SignedInfo must be a direct child of ds:Signature", ErrInvalidInput)
	}

	if state.soapBodyCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one SOAP Body, got %d", ErrInvalidInput, state.soapBodyCount)
	}

	if state.directSOAPBodyCount != 1 {
		return fmt.Errorf("%w: signed XML SOAP Body must be the direct child of the SOAP Envelope", ErrInvalidInput)
	}

	if state.expectedIDCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one XML ID with value %q, got %d", ErrInvalidInput, expectedID, state.expectedIDCount)
	}

	if state.expectedBodyCount != 1 {
		return fmt.Errorf("%w: signed XML SOAP Body must have wsu:Id %q", ErrInvalidInput, expectedID)
	}

	if state.expectedReferenceCount != 1 {
		return fmt.Errorf("%w: signed XML must contain exactly one direct ds:Reference URI=\"#%s\", got %d", ErrInvalidInput, expectedID, state.expectedReferenceCount)
	}

	return nil
}

func xmlDocumentRoot(document []byte) (xml.Name, error) {
	decoder := xml.NewDecoder(bytes.NewReader(document))
	// Treat declared ASCII-compatible encodings as byte-compatible while reading an ASCII root tag.
	decoder.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	start, _, err := scanXMLDocumentRoot(decoder)
	if err != nil {
		return xml.Name{}, err
	}

	return start.Name, nil
}

func collectSOAPVerificationState(decoder *xml.Decoder, root xml.StartElement, expectedID string) (soapVerificationState, error) {
	var (
		state          soapVerificationState
		transformState = soapBodyReferenceTransformState{
			referenceDepth:  -1,
			transformsDepth: -1,
		}
		stack = make([]xml.Name, 0, 16)
	)

	if err := observeXMLVerificationStart(&state, &transformState, root, expectedID, stack); err != nil {
		return soapVerificationState{}, err
	}

	stack = append(stack, root.Name)

	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return soapVerificationState{}, fmt.Errorf("%w: signed XML must be well-formed: %w", ErrInvalidInput, err)
		}

		switch tok := token.(type) {
		case xml.StartElement:
			if err := observeXMLVerificationStart(&state, &transformState, tok, expectedID, stack); err != nil {
				return soapVerificationState{}, err
			}

			stack = append(stack, tok.Name)
		case xml.EndElement:
			if len(stack) > 0 {
				if err := transformState.observeEnd(len(stack) - 1); err != nil {
					return soapVerificationState{}, err
				}

				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(tok)) != 0 {
				return soapVerificationState{}, fmt.Errorf("%w: signed XML must not contain text outside the document element", ErrInvalidInput)
			}
		case xml.Directive:
			return soapVerificationState{}, fmt.Errorf("%w: signed XML directives and DTDs are not allowed", ErrInvalidInput)
		default:
			continue
		}
	}

	return state, nil
}

func observeXMLVerificationStart(state *soapVerificationState, transformState *soapBodyReferenceTransformState, start xml.StartElement, expectedID string, stack []xml.Name) error {
	if err := validateUniqueXMLAttributes(start); err != nil {
		return err
	}

	if err := transformState.observeStart(start, expectedID, stack); err != nil {
		return err
	}

	observeXMLVerificationElement(state, start, expectedID, stack)

	return nil
}

func (state *soapBodyReferenceTransformState) observeStart(start xml.StartElement, expectedID string, ancestors []xml.Name) error {
	depth := len(ancestors)
	if state.referenceDepth < 0 {
		if isDirectExpectedSOAPBodyReference(start, expectedID, ancestors) {
			state.referenceDepth = depth
			state.transformsDepth = -1
			state.transformsContainerCount = 0
			state.transformElementCount = 0
			state.transformAlgorithm = ""
		}

		return nil
	}

	if isDSigReference(start.Name) {
		return fmt.Errorf("%w: SOAP Body ds:Reference must not contain a nested ds:Reference", ErrInvalidInput)
	}

	if start.Name.Local == "Transforms" {
		if start.Name.Space != xmlnsDSig {
			return fmt.Errorf("%w: SOAP Body reference Transforms must use the XML Signature namespace", ErrInvalidInput)
		}

		if depth != state.referenceDepth+1 {
			return fmt.Errorf("%w: ds:Transforms must be a direct child of the SOAP Body ds:Reference", ErrInvalidInput)
		}

		state.transformsContainerCount++
		if state.transformsContainerCount > 1 {
			return fmt.Errorf("%w: SOAP Body ds:Reference must contain at most one direct ds:Transforms", ErrInvalidInput)
		}

		state.transformsDepth = depth

		return nil
	}

	if start.Name.Local == "Transform" {
		if start.Name.Space != xmlnsDSig {
			if state.transformsDepth >= 0 && depth == state.transformsDepth+1 {
				return fmt.Errorf("%w: SOAP Body ds:Transforms may contain only direct ds:Transform elements", ErrInvalidInput)
			}

			return fmt.Errorf("%w: SOAP Body reference Transform must use the XML Signature namespace", ErrInvalidInput)
		}

		if state.transformsDepth < 0 || depth != state.transformsDepth+1 ||
			len(ancestors) == 0 || !isDSigTransforms(ancestors[len(ancestors)-1]) {
			return fmt.Errorf("%w: ds:Transform must be a direct child of ds:Transforms", ErrInvalidInput)
		}

		state.transformElementCount++
		if state.transformElementCount == 1 {
			state.transformAlgorithm = xmlAlgorithmAttribute(start)
		}

		return nil
	}

	if state.transformsDepth >= 0 && depth == state.transformsDepth+1 {
		return fmt.Errorf("%w: SOAP Body ds:Transforms may contain only direct ds:Transform elements", ErrInvalidInput)
	}

	return nil
}

func (state *soapBodyReferenceTransformState) observeEnd(depth int) error {
	if depth == state.transformsDepth {
		state.transformsDepth = -1
	}

	if depth != state.referenceDepth {
		return nil
	}

	err := state.validate()
	state.referenceDepth = -1
	state.transformsDepth = -1

	return err
}

func (state *soapBodyReferenceTransformState) validate() error {
	if state.transformsContainerCount == 0 {
		return nil
	}

	if state.transformElementCount != 1 {
		return fmt.Errorf("%w: SOAP Body ds:Transforms must contain exactly one direct ds:Transform, got %d", ErrInvalidInput, state.transformElementCount)
	}

	algorithm := state.transformAlgorithm
	if algorithm == "" {
		return fmt.Errorf("%w: SOAP Body ds:Transform Algorithm must not be empty", ErrInvalidInput)
	}

	if algorithm != xmlAlgorithmExclusiveCanonicalization {
		return fmt.Errorf("%w: ds:Transform Algorithm is not allowed for the SOAP Body reference; only %q is supported", ErrInvalidInput, xmlAlgorithmExclusiveCanonicalization)
	}

	// CanonicalizationMethod, DigestMethod, and SignatureMethod remain native
	// KalkanCrypt policy: the repository does not define a stable allowlist for
	// those installation-dependent algorithms, so guessing one here would break
	// supported signatures. This wrapper independently constrains only transforms.
	return nil
}

func observeXMLVerificationElement(state *soapVerificationState, start xml.StartElement, expectedID string, ancestors []xml.Name) {
	depth := len(ancestors)
	if depth == 0 {
		state.documentElementCount++
		if state.documentElementCount == 1 {
			state.root = start.Name
		}
	}

	state.expectedIDCount += matchingXMLIDCount(start, expectedID)
	if isDSigSignature(start.Name) {
		state.signatureCount++
	}

	if isDSigSignedInfo(start.Name) {
		state.signedInfoCount++
		if depth > 0 && isDSigSignature(ancestors[depth-1]) {
			state.directSignedInfoCount++
		}
	}

	if isDirectExpectedSOAPBodyReference(start, expectedID, ancestors) {
		state.expectedReferenceCount++
	}

	if !isSOAPBody(start.Name) {
		return
	}

	state.soapBodyCount++
	if len(ancestors) != 1 || !isSOAPEnvelope(state.root) || start.Name.Space != state.root.Space {
		return
	}

	state.directSOAPBodyCount++
	if hasWSUID(start, expectedID) {
		state.expectedBodyCount++
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

func isDSigTransforms(name xml.Name) bool {
	return name.Local == "Transforms" && name.Space == xmlnsDSig
}

func isDirectExpectedSOAPBodyReference(start xml.StartElement, expectedID string, ancestors []xml.Name) bool {
	depth := len(ancestors)

	return isDSigReference(start.Name) && depth >= 2 &&
		isDSigSignedInfo(ancestors[depth-1]) && isDSigSignature(ancestors[depth-2]) &&
		referenceURI(start) == "#"+expectedID
}

func hasWSUID(start xml.StartElement, id string) bool {
	for _, attr := range start.Attr {
		if attr.Name.Space == xmlnsWSU && attr.Name.Local == "Id" &&
			strings.Trim(attr.Value, xmlWhitespaceChars) == id {
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
		switch attr.Name {
		case xml.Name{Space: xmlnsWSU, Local: "Id"},
			xml.Name{Space: xmlnsXML, Local: "id"},
			xml.Name{Local: "Id"},
			xml.Name{Local: "ID"}:
			if strings.Trim(attr.Value, xmlWhitespaceChars) == id {
				count++
			}
		}
	}

	return count
}

func referenceURI(start xml.StartElement) string {
	for _, attr := range start.Attr {
		if attr.Name.Space == "" && attr.Name.Local == "URI" {
			return attr.Value
		}
	}

	return ""
}

func xmlAlgorithmAttribute(start xml.StartElement) string {
	for _, attr := range start.Attr {
		if attr.Name.Space == "" && attr.Name.Local == "Algorithm" {
			return attr.Value
		}
	}

	return ""
}

func validateUniqueXMLAttributes(start xml.StartElement) error {
	// Eight attributes cap the allocation-free path at 28 comparisons. Larger
	// elements use a map so adversarial input cannot cause quadratic work.
	const maxLinearAttributeCount = 8

	if len(start.Attr) <= maxLinearAttributeCount {
		for index, attr := range start.Attr {
			for previous := range index {
				if attr.Name == start.Attr[previous].Name {
					return fmt.Errorf("%w: signed XML element %q contains duplicate attribute %q", ErrInvalidInput, start.Name.Local, attr.Name.Local)
				}
			}
		}

		return nil
	}

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
