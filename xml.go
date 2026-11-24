package kalkan

import (
	"bytes"
	"context"
	"fmt"

	"github.com/skarm/kalkan/ckalkan"
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
	// XML is a nonempty in-memory document with raw or automatic encoding.
	// File sources and other source encodings are unsupported.
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
	// XML is a nonempty signed in-memory document with raw or automatic encoding.
	// File sources and other source encodings are unsupported.
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
	// XML is a full SOAP envelope or a payload for a new envelope when WrapSOAP is true.
	// It must be a nonempty in-memory source with raw or automatic encoding.
	// The client rejects file sources.
	XML Source
	// BodyID is the wsu:Id value of the SOAP Body that KalkanCrypt signs. It
	// is required whether XML is wrapped by this package or supplied as a full
	// SOAP envelope.
	BodyID string
	// WrapSOAP adds a minimal SOAP envelope to XML before the SDK signs it.
	WrapSOAP bool
	// Canonicalization selects the XML canonicalization algorithm.
	// Select XMLCanonicalizationExclusive for compatibility with VerifyXML's
	// SOAP Body transform policy.
	// Other modes remain available for native consumers.
	Canonicalization XMLCanonicalization
	// CertificateTimeCheck controls certificate-time validation.
	CertificateTimeCheck CertificateTimeCheck
}

// SignedXML contains a signed document returned by [Client.SignXML] or
// [Client.SignWSSE].
type SignedXML struct {
	// XML contains the signed XML document.
	XML []byte
}

// SignXML signs req.XML and returns the signed document.
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

	flags, err := xmlSignatureFlags(req.Canonicalization, req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	out, err := withOperationsResult(c, ctx, "SignXML", func(operations xmlOperations) ([]byte, error) {
		return operations.SignXML(ckalkan.SignXMLRequest{
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

// VerifyXML verifies req.XML and returns native diagnostics.
// A SOAP Body reference can omit Transforms or contain one exclusive
// canonicalization Transform.
// That transform can contain at most one InclusiveNamespaces parameter with a
// PrefixList attribute.
// PrefixList can be empty.
// The client rejects other transform parameters, attributes, and non-whitespace
// text before native verification.
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

	flags, err := xmlSignatureFlags(req.Canonicalization, req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	if err := validateXMLVerificationStructure(input, req.ExpectedBodyID); err != nil {
		return nil, err
	}

	info, err := withOperationsResult(c, ctx, "VerifyXML", func(operations xmlOperations) (string, error) {
		return operations.VerifyXML(req.Alias, flags, input)
	})
	if err != nil {
		return nil, err
	}

	return &Verification{Info: info}, nil
}

// SignWSSE signs req.XML with WS-Security and returns the signed SOAP document.
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

	flags, err := xmlSignatureFlags(req.Canonicalization, req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	out, err := withOperationsResult(c, ctx, "SignWSSE", func(operations xmlOperations) ([]byte, error) {
		return operations.SignWSSE(ckalkan.SignWSSERequest{
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

func xmlSignatureFlags(canonicalization XMLCanonicalization, check CertificateTimeCheck) (ckalkan.Flag, error) {
	flags, err := xmlCanonicalizationFlag(canonicalization)
	if err != nil {
		return 0, err
	}

	checkFlags, err := certificateTimeCheckFlag(check)
	if err != nil {
		return 0, err
	}

	return flags | checkFlags, nil
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
