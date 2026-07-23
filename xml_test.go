package kalkan

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/skarm/kalkan/ckalkan"
)

func TestSignXMLUsesRequestedCanonicalization(t *testing.T) {
	native := &fakeNative{
		signXMLFunc: func(req ckalkan.SignXMLRequest) ([]byte, error) {
			wantFlags := ckalkan.XMLExclC14N | ckalkan.NoCheckCertTime
			if req.Flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", req.Flags, wantFlags)
			}
			return []byte("<signed/>"), nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignXML(context.Background(), SignXMLRequest{
		XML:                  Bytes([]byte("<root/>")),
		Canonicalization:     XMLCanonicalizationExclusive,
		CertificateTimeCheck: SkipCertificateTimeCheck,
		SignNodeID:           "node-1",
		ParentSignNode:       "parent",
		ParentNamespace:      "urn:test",
	})
	if err != nil {
		t.Fatalf("SignXML returned error: %v", err)
	}
}

func TestSignXMLDoesNotCopyOutput(t *testing.T) {
	signedXML := []byte("<signed/>")
	client := &Client{library: &fakeNative{
		signXMLFunc: func(ckalkan.SignXMLRequest) ([]byte, error) {
			return signedXML, nil
		},
	}}

	signed, err := client.SignXML(context.Background(), SignXMLRequest{
		XML: Bytes([]byte("<root/>")),
	})
	if err != nil {
		t.Fatalf("SignXML returned error: %v", err)
	}
	if !sameByteSliceBacking(signed.XML, signedXML) {
		t.Fatal("SignXML cloned native XML output")
	}
}

func TestVerifyXMLUsesRequestedCanonicalization(t *testing.T) {
	native := &fakeNative{
		verifyXMLFunc: func(alias string, flags ckalkan.Flag, xml []byte) (string, error) {
			wantFlags := ckalkan.XMLInclC14N11Comment | ckalkan.NoCheckCertTime
			if flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, wantFlags)
			}
			return "Verify - OK", nil
		},
	}
	client := &Client{library: native}

	verification, err := client.VerifyXML(context.Background(), VerifyXMLRequest{
		XML:                  Bytes([]byte("<signed/>")),
		Canonicalization:     XMLCanonicalizationInclusive11WithComments,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("VerifyXML returned error: %v", err)
	}
	if verification.Info != "Verify - OK" {
		t.Fatalf("verification info = %q", verification.Info)
	}
}

func TestBundledXMLExample(t *testing.T) {
	data, err := os.ReadFile("testdata/examples/test_xml.xml")
	if err != nil {
		t.Fatalf("read bundled XML example: %v", err)
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	var root xml.Name
	hasRussianLangAttr := false
	hasCyrillicText := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("parse bundled XML example: %v", err)
		}

		start, ok := token.(xml.StartElement)
		if !ok {
			if text, ok := token.(xml.CharData); ok && hasCyrillic(text) {
				hasCyrillicText = true
			}

			continue
		}
		if root.Local == "" {
			root = start.Name
		}
		for _, attr := range start.Attr {
			if attr.Name.Local == "lang" && attr.Value == "ru" {
				hasRussianLangAttr = true
			}
		}
	}

	if root.Local != "companies" {
		t.Fatalf("XML example root = %q, want companies", root.Local)
	}
	if !bytes.Contains(data, []byte(`encoding="UTF-8"`)) {
		t.Fatal("XML example must declare UTF-8 encoding")
	}
	if !hasCyrillicText {
		t.Fatal("XML example must contain Cyrillic UTF-8 text")
	}
	if !hasRussianLangAttr || !bytes.Contains(data, []byte(`gallery-url=`)) {
		t.Fatal("XML example must contain realistic attributes")
	}
	if !bytes.Contains(data, []byte(`<ext/>`)) || !bytes.Contains(data, []byte(`<info/>`)) {
		t.Fatal("XML example must contain empty elements")
	}
}

func TestSignWSSEWrapsSOAPBodyWhenRequested(t *testing.T) {
	native := &fakeNative{
		signWSSEFunc: func(req ckalkan.SignWSSERequest) ([]byte, error) {
			x := string(req.XML)
			if !strings.Contains(x, `<soap:Envelope`) {
				t.Fatalf("WSSE input does not contain SOAP envelope: %s", x)
			}
			if !strings.Contains(x, `wsu:Id="body-id"`) {
				t.Fatalf("WSSE input does not contain body id: %s", x)
			}
			if !strings.Contains(x, `<payload>ok</payload>`) {
				t.Fatalf("WSSE input does not contain payload: %s", x)
			}
			if req.SignNodeID != "body-id" {
				t.Fatalf("sign node id = %q, want body-id", req.SignNodeID)
			}
			return []byte("<signed-wsse/>"), nil
		},
	}
	client := &Client{library: native}

	signed, err := client.SignWSSE(context.Background(), SignWSSERequest{
		XML:      Bytes([]byte("<payload>ok</payload>")),
		BodyID:   "body-id",
		WrapSOAP: true,
	})
	if err != nil {
		t.Fatalf("SignWSSE returned error: %v", err)
	}
	if string(signed.XML) != "<signed-wsse/>" {
		t.Fatalf("signed WSSE XML = %q", signed.XML)
	}
}

func TestSignWSSEDoesNotCopyOutput(t *testing.T) {
	signedWSSE := []byte("<signed-wsse/>")
	client := &Client{library: &fakeNative{
		signWSSEFunc: func(ckalkan.SignWSSERequest) ([]byte, error) {
			return signedWSSE, nil
		},
	}}

	signed, err := client.SignWSSE(context.Background(), SignWSSERequest{
		XML:    Bytes([]byte("<payload/>")),
		BodyID: "body-id",
	})
	if err != nil {
		t.Fatalf("SignWSSE returned error: %v", err)
	}
	if !sameByteSliceBacking(signed.XML, signedWSSE) {
		t.Fatal("SignWSSE cloned native XML output")
	}
}

func TestSignWSSERejectsInvalidWrappedPayload(t *testing.T) {
	tests := []struct {
		name    string
		bodyID  string
		payload string
		want    string
	}{
		{
			name:    "two root elements",
			bodyID:  "body-id",
			payload: "<first/><second/>",
			want:    "single XML element",
		},
		{
			name:    "closes soap body",
			bodyID:  "body-id",
			payload: "<payload></soap:Body>",
			want:    "well-formed XML element",
		},
		{
			name:    "trailing text",
			bodyID:  "body-id",
			payload: "<payload/> trailing",
			want:    "trailing text",
		},
		{
			name:    "empty body id",
			bodyID:  "",
			payload: "<payload/>",
			want:    "SOAP BodyID is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			native := &fakeNative{
				signWSSEFunc: func(req ckalkan.SignWSSERequest) ([]byte, error) {
					t.Error("SignWSSE called native SignWSSE for invalid SOAP wrapping input")
					return nil, nil
				},
			}
			client := &Client{library: native}

			_, err := client.SignWSSE(context.Background(), SignWSSERequest{
				XML:      Bytes([]byte(test.payload)),
				BodyID:   test.bodyID,
				WrapSOAP: true,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("SignWSSE error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestWrapSOAPBodyPreservesPayloadAndWSUId(t *testing.T) {
	wrapped, err := wrapSOAPBody([]byte("<payload><value>ok</value></payload>"), "body-id")
	if err != nil {
		t.Fatalf("wrapSOAPBody returned error: %v", err)
	}
	if len(wrapped) == cap(wrapped) || wrapped[:len(wrapped)+1][len(wrapped)] != 0 {
		t.Fatal("wrapped SOAP lacks reserved trailing NUL")
	}

	type body struct {
		ID      string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr"`
		Payload struct {
			Value string `xml:"value"`
		} `xml:"payload"`
	}
	type envelope struct {
		Body body `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	}

	var env envelope
	if err := xml.Unmarshal(wrapped, &env); err != nil {
		t.Fatalf("wrapped XML is not well-formed: %v\n%s", err, wrapped)
	}
	if env.Body.ID != "body-id" {
		t.Fatalf("wsu:Id = %q, want body-id in %s", env.Body.ID, wrapped)
	}
	if env.Body.Payload.Value != "ok" {
		t.Fatalf("payload value = %q, want ok in %s", env.Body.Payload.Value, wrapped)
	}
}

func validSignedSOAP(referenceURI, extraBody string) string {
	return `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><soap:Header><ds:Signature><ds:SignedInfo><ds:Reference URI="` + referenceURI + `"/></ds:SignedInfo></ds:Signature></soap:Header><soap:Body wsu:Id="TheBody"><payload>ok</payload></soap:Body>` + extraBody + `</soap:Envelope>`
}

func hasCyrillic(data []byte) bool {
	for _, r := range string(data) {
		if unicode.In(r, unicode.Cyrillic) {
			return true
		}
	}

	return false
}

func TestWrapSOAPBodyRejectsInvalidBodyID(t *testing.T) {
	tests := []string{
		"bad id",
		"1starts-with-digit",
		"bad:id",
		"bad/id",
	}

	for _, bodyID := range tests {
		t.Run(bodyID, func(t *testing.T) {
			_, err := wrapSOAPBody([]byte("<payload/>"), bodyID)
			if err == nil || !strings.Contains(err.Error(), "SOAP BodyID") {
				t.Fatalf("wrapSOAPBody(%q) error = %v, want invalid BodyID error", bodyID, err)
			}
		})
	}
}

func TestXMLNCNameGrammar(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "ASCII", value: "body-id", want: true},
		{name: "underscore", value: "_body", want: true},
		{name: "combining mark", value: "a\u0301", want: true},
		{name: "middle dot", value: "a\u00b7b", want: true},
		{name: "undertie", value: "a\u203fb", want: true},
		{name: "zero width non-joiner", value: "\u200cbody", want: true},
		{name: "non-ASCII digit in name-start range", value: "\u0660body", want: true},
		{name: "supplementary plane", value: "\U00010000body", want: true},
		{name: "replacement character", value: "\ufffdbody", want: true},
		{name: "empty", value: "", want: false},
		{name: "ASCII digit first", value: "1body", want: false},
		{name: "colon", value: "body:id", want: false},
		{name: "whitespace", value: "body id", want: false},
		{name: "excluded Greek question mark", value: "\u037ebody", want: false},
		{name: "above XML name range", value: "\U000f0000body", want: false},
		{name: "invalid UTF-8", value: string([]byte{'b', 0xff}), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isXMLNCName(test.value); got != test.want {
				t.Fatalf("isXMLNCName(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestWrapSOAPBodyRejectsInvalidPayloads(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{name: "empty", payload: " \n\t ", want: "SOAP payload is empty"},
		{name: "two root elements", payload: "<first/><second/>", want: "single XML element"},
		{name: "closes soap body", payload: "<payload></soap:Body>", want: "well-formed XML element"},
		{name: "trailing text", payload: "<payload/> trailing", want: "trailing text"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := wrapSOAPBody([]byte(test.payload), "body-id")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wrapSOAPBody error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSignWSSEUsesRequestedCanonicalization(t *testing.T) {
	native := &fakeNative{
		signWSSEFunc: func(req ckalkan.SignWSSERequest) ([]byte, error) {
			wantFlags := ckalkan.XMLExclC14NComment
			if req.Flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", req.Flags, wantFlags)
			}
			return []byte("<signed-wsse/>"), nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignWSSE(context.Background(), SignWSSERequest{
		XML:              Bytes([]byte("<soap:Envelope/>")),
		BodyID:           "TheBody",
		Canonicalization: XMLCanonicalizationExclusiveWithComments,
	})
	if err != nil {
		t.Fatalf("SignWSSE returned error: %v", err)
	}
}

func TestSignWSSERejectsInvalidBodyID(t *testing.T) {
	native := &fakeNative{
		signWSSEFunc: func(req ckalkan.SignWSSERequest) ([]byte, error) {
			t.Error("SignWSSE called native SignWSSE with invalid BodyID and WrapSOAP=false")
			return nil, nil
		},
	}
	client := &Client{library: native}

	tests := []struct {
		name   string
		bodyID string
	}{
		{name: "empty", bodyID: ""},
		{name: "contains whitespace", bodyID: "bad id"},
		{name: "starts with digit", bodyID: "1starts-with-digit"},
		{name: "contains colon", bodyID: "bad:id"},
		{name: "leading whitespace", bodyID: " body-id"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.SignWSSE(context.Background(), SignWSSERequest{
				XML:      Bytes([]byte("<soap:Envelope/>")),
				BodyID:   test.bodyID,
				WrapSOAP: false,
			})
			if err == nil || !strings.Contains(err.Error(), "SOAP BodyID") {
				t.Fatalf("SignWSSE error = %v, want BodyID rejection", err)
			}
		})
	}
}

func TestVerifyXMLPropagatesNativeErrors(t *testing.T) {
	nativeErr := errors.New("native verify failed")
	native := &fakeNative{
		verifyXMLFunc: func(alias string, flags ckalkan.Flag, xml []byte) (string, error) {
			if alias != "verify-key" {
				t.Fatalf("alias = %q, want verify-key", alias)
			}
			if flags != ckalkan.XMLInclC14N {
				t.Fatalf("flags = %#x, want XMLInclC14N", flags)
			}
			if string(xml) != "<signed/>" {
				t.Fatalf("xml = %q, want signed XML", xml)
			}
			return "", nativeErr
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyXML(context.Background(), VerifyXMLRequest{
		Alias: "verify-key",
		XML:   Bytes([]byte("<signed/>")),
	})
	if !errors.Is(err, nativeErr) {
		t.Fatalf("VerifyXML error = %v, want native error", err)
	}
}

func TestSignXMLRejectsFileSource(t *testing.T) {
	client := &Client{library: &fakeNative{}}

	_, err := client.SignXML(context.Background(), SignXMLRequest{
		XML: File("/tmp/document.xml"),
	})
	if err == nil || !strings.Contains(err.Error(), "XML file sources are not supported") {
		t.Fatalf("SignXML error = %v, want unsupported file source", err)
	}
}

func TestXMLMethodsRequireSource(t *testing.T) {
	native := &fakeNative{
		signXMLFunc: func(req ckalkan.SignXMLRequest) ([]byte, error) {
			t.Error("SignXML called native SignXML without XML source")
			return nil, nil
		},
		verifyXMLFunc: func(alias string, flags ckalkan.Flag, xml []byte) (string, error) {
			t.Error("VerifyXML called native VerifyXML without XML source")
			return "", nil
		},
		signWSSEFunc: func(req ckalkan.SignWSSERequest) ([]byte, error) {
			t.Error("SignWSSE called native SignWSSE without XML source")
			return nil, nil
		},
	}
	client := &Client{library: native}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "SignXML",
			call: func() error {
				_, err := client.SignXML(context.Background(), SignXMLRequest{})
				return err
			},
		},
		{
			name: "VerifyXML",
			call: func() error {
				_, err := client.VerifyXML(context.Background(), VerifyXMLRequest{})
				return err
			},
		},
		{
			name: "SignWSSE",
			call: func() error {
				_, err := client.SignWSSE(context.Background(), SignWSSERequest{BodyID: "body-id"})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if err == nil || !strings.Contains(err.Error(), "XML source is required") {
				t.Fatalf("%s error = %v, want missing XML source rejection", test.name, err)
			}
		})
	}
}

func TestSignXMLRejectsEmptyInput(t *testing.T) {
	native := &fakeNative{
		signXMLFunc: func(req ckalkan.SignXMLRequest) ([]byte, error) {
			t.Error("SignXML called native SignXML for empty XML input")
			return nil, nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignXML(context.Background(), SignXMLRequest{
		XML: Bytes([]byte(" \n\t ")),
	})
	if err == nil || !strings.Contains(err.Error(), "XML input is empty") {
		t.Fatalf("SignXML error = %v, want empty XML input error", err)
	}
}

func TestSignXMLRejectsEncodedSources(t *testing.T) {
	tests := []struct {
		name   string
		source Source
	}{
		{name: "base64", source: Base64([]byte("<root/>"))},
		{name: "pem", source: PEM([]byte("<root/>"))},
		{name: "der", source: DER([]byte("<root/>"))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			native := &fakeNative{
				signXMLFunc: func(req ckalkan.SignXMLRequest) ([]byte, error) {
					t.Error("SignXML called native SignXML for unsupported XML source encoding")
					return nil, nil
				},
			}
			client := &Client{library: native}

			_, err := client.SignXML(context.Background(), SignXMLRequest{
				XML: test.source,
			})
			if err == nil || !strings.Contains(err.Error(), "XML source encoding") {
				t.Fatalf("SignXML error = %v, want unsupported XML source encoding", err)
			}
		})
	}
}

func TestSignXMLValidatesBeforeNativeLock(t *testing.T) {
	enteredHash := make(chan struct{})
	releaseHash := make(chan struct{})
	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			close(enteredHash)
			<-releaseHash
			return []byte("digest"), nil
		},
	}
	client := &Client{library: native}

	hashDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("payload"))})
		hashDone <- err
	}()
	<-enteredHash

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.SignXML(ctx, SignXMLRequest{XML: Bytes([]byte(" \n\t "))})
	if err == nil || !strings.Contains(err.Error(), "XML input is empty") {
		t.Fatalf("SignXML error = %v, want XML validation error without waiting for native lock", err)
	}

	close(releaseHash)
	if err := <-hashDone; err != nil {
		t.Fatalf("in-flight Hash returned error: %v", err)
	}
}
