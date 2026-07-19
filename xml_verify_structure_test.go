package kalkan

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestVerifyXMLSOAPBinding(t *testing.T) {
	tests := []struct {
		name     string
		document string
		bodyID   string
		want     string
	}{
		{"valid body reference", validSignedSOAP("#TheBody", ""), "TheBody", ""},
		{"different reference", validSignedSOAP("#Other", ""), "TheBody", `exactly one direct ds:Reference URI="#TheBody"`},
		{"reference outside SignedInfo", strings.Replace(validSignedSOAP("#Other", ""), "</soap:Header>", `<ds:Reference URI="#TheBody"/></soap:Header>`, 1), "TheBody", "exactly one direct ds:Reference"},
		{"extra SignedInfo in Object", strings.Replace(validSignedSOAP("#Other", ""), "</ds:Signature>", `<ds:Object><ds:SignedInfo><ds:Reference URI="#TheBody"/></ds:SignedInfo></ds:Object></ds:Signature>`, 1), "TheBody", "exactly one ds:SignedInfo"},
		{"SignedInfo nested in Object", nestedSignedInfoSOAP(), "TheBody", "must be a direct child"},
		{"wsu Id collision", validSignedSOAP("#TheBody", `<extra wsu:Id="TheBody"/>`), "TheBody", "exactly one XML ID"},
		{"xml id collision", validSignedSOAP("#TheBody", `<extra xml:id="TheBody"/>`), "TheBody", "exactly one XML ID"},
		{"normalized xml id collision", validSignedSOAP("#TheBody", `<extra xml:id="&#x20;&#x9;TheBody&#xD;&#xA;"/>`), "TheBody", "exactly one XML ID"},
		{"Id collision", validSignedSOAP("#TheBody", `<extra Id="TheBody"/>`), "TheBody", "exactly one XML ID"},
		{"ID collision", validSignedSOAP("#TheBody", `<extra ID="TheBody"/>`), "TheBody", "exactly one XML ID"},
		{"two SOAP Bodies", validSignedSOAP("#TheBody", `<soap:Body wsu:Id="Other"/>`), "TheBody", "exactly one SOAP Body"},
		{"two Signatures", strings.Replace(validSignedSOAP("#TheBody", ""), "</soap:Header>", `<ds:Signature/></soap:Header>`, 1), "TheBody", "exactly one ds:Signature"},
		{"additional signed reference", strings.Replace(validSignedSOAP("#TheBody", ""), "</ds:SignedInfo>", `<ds:Reference URI="#Other"/></ds:SignedInfo>`, 1), "TheBody", ""},
		{"duplicate body reference", strings.Replace(validSignedSOAP("#TheBody", ""), "</ds:SignedInfo>", `<ds:Reference URI="#TheBody"/></ds:SignedInfo>`, 1), "TheBody", "exactly one direct ds:Reference"},
		{"duplicate URI attribute", strings.Replace(validSignedSOAP("#TheBody", ""), `URI="#TheBody"`, `URI="#TheBody" URI="#Other"`, 1), "TheBody", "duplicate attribute"},
		{"SOAP 1.1 without Body ID", validSignedSOAP("#TheBody", ""), "", "ExpectedBodyID is required"},
		{"SOAP 1.2 without Body ID", strings.ReplaceAll(validSignedSOAP("#TheBody", ""), xmlnsSOAP, xmlnsSOAP12), "", "ExpectedBodyID is required"},
		{"Body without wsu Id", strings.Replace(validSignedSOAP("#TheBody", ""), `wsu:Id="TheBody"`, `Id="TheBody"`, 1), "TheBody", "SOAP Body must have wsu:Id"},
		{"nested Body", strings.Replace(validSignedSOAP("#TheBody", ""), `<soap:Body wsu:Id="TheBody"><payload>ok</payload></soap:Body>`, `<wrapper><soap:Body wsu:Id="TheBody"><payload>ok</payload></soap:Body></wrapper>`, 1), "TheBody", "direct child"},
		{"DOCTYPE", `<!DOCTYPE soap:Envelope SYSTEM "http://127.0.0.1/x">` + validSignedSOAP("#TheBody", ""), "TheBody", "DTDs are not allowed"},
		{"multiple document roots", validSignedSOAP("#TheBody", "") + `<extra/>`, "TheBody", "exactly one document element"},
		{"signed generic XML", validSignedGenericXML(), "", ""},
		{"unsigned generic XML", `<document/>`, "", ""},
		{"generic nested SignedInfo", strings.Replace(validSignedGenericXML(), `</ds:Signature>`, `<ds:Object><ds:SignedInfo/></ds:Object></ds:Signature>`, 1), "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nativeCalls := 0
			native := &fakeNative{
				verifyXMLFunc: func(string, ckalkan.Flag, []byte) (string, error) {
					nativeCalls++
					return "Verify - OK", nil
				},
			}
			client := &Client{library: native}

			verification, err := client.VerifyXML(context.Background(), VerifyXMLRequest{
				XML:            Bytes([]byte(test.document)),
				ExpectedBodyID: test.bodyID,
			})
			if test.want != "" {
				if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("VerifyXML error = %v, want ErrInvalidInput containing %q", err, test.want)
				}
				if nativeCalls != 0 {
					t.Fatalf("native VerifyXML calls = %d, want 0 for structurally invalid XML", nativeCalls)
				}
				return
			}

			if err != nil {
				t.Fatalf("VerifyXML returned error: %v", err)
			}
			if verification == nil || verification.Info != "Verify - OK" {
				t.Fatalf("VerifyXML result = %#v, want native verification info", verification)
			}
			if nativeCalls != 1 {
				t.Fatalf("native VerifyXML calls = %d, want 1", nativeCalls)
			}
		})
	}
}

func TestVerifyXMLSOAPBodyTransformPolicy(t *testing.T) {
	const (
		exclusiveCanonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#"
		xPathTransform            = "http://www.w3.org/TR/1999/REC-xpath-19991116"
		xPathFilter2Transform     = "http://www.w3.org/2002/06/xmldsig-filter2"
		xsltTransform             = "http://www.w3.org/TR/1999/REC-xslt-19991116"
		base64Transform           = "http://www.w3.org/2000/09/xmldsig#base64"
	)

	tests := []struct {
		name     string
		document string
		want     string
	}{
		{
			name:     "body Reference without Transforms",
			document: validSignedSOAP("#TheBody", ""),
		},
		{
			name:     "exclusive canonicalization Transform",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms><ds:Transform Algorithm="` + exclusiveCanonicalization + `"/></ds:Transforms>`),
		},
		{
			name:     "XPath Transform",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms><ds:Transform Algorithm="` + xPathTransform + `"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms>`),
			want:     "is not allowed for the SOAP Body reference",
		},
		{
			name:     "XPath Filter 2.0 Transform",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms><ds:Transform Algorithm="` + xPathFilter2Transform + `"/></ds:Transforms>`),
			want:     "is not allowed for the SOAP Body reference",
		},
		{
			name:     "XSLT Transform",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms><ds:Transform Algorithm="` + xsltTransform + `"/></ds:Transforms>`),
			want:     "is not allowed for the SOAP Body reference",
		},
		{
			name:     "Base64 Transform",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms><ds:Transform Algorithm="` + base64Transform + `"/></ds:Transforms>`),
			want:     "is not allowed for the SOAP Body reference",
		},
		{
			name:     "unknown Transform",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms><ds:Transform Algorithm="urn:example:unknown-transform"/></ds:Transforms>`),
			want:     "is not allowed for the SOAP Body reference",
		},
		{
			name:     "empty Transform Algorithm",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms><ds:Transform Algorithm=""/></ds:Transforms>`),
			want:     "ds:Transform Algorithm must not be empty",
		},
		{
			name:     "missing Transform Algorithm",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms><ds:Transform/></ds:Transforms>`),
			want:     "ds:Transform Algorithm must not be empty",
		},
		{
			name:     "namespaced Transform Algorithm",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms xmlns:fake="urn:example:fake"><ds:Transform fake:Algorithm="` + exclusiveCanonicalization + `"/></ds:Transforms>`),
			want:     "ds:Transform Algorithm must not be empty",
		},
		{
			name:     "multiple Transforms",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms><ds:Transform Algorithm="` + exclusiveCanonicalization + `"/><ds:Transform Algorithm="` + xPathTransform + `"/></ds:Transforms>`),
			want:     "exactly one direct ds:Transform, got 2",
		},
		{
			name: "Transform on another Reference is ignored",
			document: strings.Replace(
				validSignedSOAP("#TheBody", ""),
				"</ds:SignedInfo>",
				`<ds:Reference URI="#Other"><ds:Transforms><ds:Transform Algorithm="`+xPathTransform+`"/></ds:Transforms></ds:Reference></ds:SignedInfo>`,
				1,
			),
		},
		{
			name:     "Transform namespace spoofing",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms xmlns:fake="urn:example:fake"><fake:Transform Algorithm="` + exclusiveCanonicalization + `"/></ds:Transforms>`),
			want:     "ds:Transforms may contain only direct ds:Transform elements",
		},
		{
			name:     "Transforms namespace spoofing",
			document: signedSOAPWithBodyReferenceContent(`<fake:Transforms xmlns:fake="urn:example:fake"><ds:Transform Algorithm="` + exclusiveCanonicalization + `"/></fake:Transforms>`),
			want:     "Transforms must use the XML Signature namespace",
		},
		{
			name:     "empty Transforms",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transforms/>`),
			want:     "exactly one direct ds:Transform, got 0",
		},
		{
			name:     "Transform outside Transforms",
			document: signedSOAPWithBodyReferenceContent(`<ds:Transform Algorithm="` + exclusiveCanonicalization + `"/>`),
			want:     "ds:Transform must be a direct child of ds:Transforms",
		},
		{
			name:     "nested Reference in body Reference",
			document: signedSOAPWithBodyReferenceContent(`<ds:Reference URI="#Other"/>`),
			want:     "SOAP Body ds:Reference must not contain a nested ds:Reference",
		},
		{
			name: "nested matching body Reference",
			document: strings.Replace(
				validSignedSOAP("#Other", ""),
				`<ds:Reference URI="#Other"/>`,
				`<ds:Reference URI="#Other"><ds:Reference URI="#TheBody"/></ds:Reference>`,
				1,
			),
			want: `exactly one direct ds:Reference URI="#TheBody"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nativeCalls := 0
			client := &Client{library: &fakeNative{
				verifyXMLFunc: func(string, ckalkan.Flag, []byte) (string, error) {
					nativeCalls++
					return "Verify - OK", nil
				},
			}}

			verification, err := client.VerifyXML(context.Background(), VerifyXMLRequest{
				XML:            Bytes([]byte(test.document)),
				ExpectedBodyID: "TheBody",
			})
			if test.want != "" {
				if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("VerifyXML error = %v, want ErrInvalidInput containing %q", err, test.want)
				}
				if nativeCalls != 0 {
					t.Fatalf("native VerifyXML calls = %d, want 0 for rejected transform policy", nativeCalls)
				}
				return
			}

			if err != nil {
				t.Fatalf("VerifyXML returned error: %v", err)
			}
			if verification == nil || verification.Info != "Verify - OK" {
				t.Fatalf("VerifyXML result = %#v, want native verification info", verification)
			}
			if nativeCalls != 1 {
				t.Fatalf("native VerifyXML calls = %d, want 1", nativeCalls)
			}
		})
	}
}

func TestValidateXMLVerificationStructureAcceptsProjectWSSETransformChain(t *testing.T) {
	document, err := os.ReadFile("testdata/examples/test_wsse.xml")
	if err != nil {
		t.Fatalf("read WS-Security example: %v", err)
	}
	// The legacy example uses the non-standard label "UTF8". Normalize only the
	// declaration so this test exercises its unchanged XML Signature structure.
	document = bytes.Replace(document, []byte(`encoding="UTF8"`), []byte(`encoding="UTF-8"`), 1)

	if err := validateXMLVerificationStructure(document, "TheBody"); err != nil {
		t.Fatalf("project WS-Security transform chain rejected: %v", err)
	}
}

func TestVerifyXMLRejectsXPathTransformBeforeNative(t *testing.T) {
	const secretPayload = "sensitive-regression-payload"
	document := signedSOAPWithBodyReferenceContent(`<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms>`)
	document = strings.Replace(document, "<payload>ok</payload>", "<payload>"+secretPayload+"</payload>", 1)

	client := &Client{library: &fakeNative{
		verifyXMLFunc: func(string, ckalkan.Flag, []byte) (string, error) {
			t.Fatal("native VerifyXML called for a SOAP Body Reference containing XPath")
			return "", nil
		},
	}}

	_, err := client.VerifyXML(context.Background(), VerifyXMLRequest{
		XML:            Bytes([]byte(document)),
		ExpectedBodyID: "TheBody",
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "is not allowed for the SOAP Body reference") {
		t.Fatalf("VerifyXML error = %v, want XPath transform policy rejection", err)
	}
	if strings.Contains(err.Error(), secretPayload) {
		t.Fatalf("VerifyXML error disclosed document payload: %v", err)
	}
}

func signedSOAPWithBodyReferenceContent(content string) string {
	return strings.Replace(
		validSignedSOAP("#TheBody", ""),
		`<ds:Reference URI="#TheBody"/>`,
		`<ds:Reference URI="#TheBody">`+content+`</ds:Reference>`,
		1,
	)
}

func validSignedGenericXML() string {
	return `<document xmlns:ds="` + xmlnsDSig + `"><ds:Signature><ds:SignedInfo><ds:Reference URI="#document"/></ds:SignedInfo></ds:Signature></document>`
}

func nestedSignedInfoSOAP() string {
	document := strings.Replace(validSignedSOAP("#TheBody", ""), "<ds:SignedInfo>", "<ds:Object><ds:SignedInfo>", 1)

	return strings.Replace(document, "</ds:SignedInfo>", "</ds:SignedInfo></ds:Object>", 1)
}

func TestVerifyXMLDoesNotCopyInput(t *testing.T) {
	document := []byte(validSignedSOAP("#TheBody", ""))
	client := &Client{library: &fakeNative{
		verifyXMLFunc: func(_ string, _ ckalkan.Flag, input []byte) (string, error) {
			if !sameByteSliceBacking(input, document) {
				t.Fatal("VerifyXML copied the caller's XML buffer")
			}

			return "Verify - OK", nil
		},
	}}

	if _, err := client.VerifyXML(context.Background(), VerifyXMLRequest{
		XML:            Bytes(document),
		ExpectedBodyID: "TheBody",
	}); err != nil {
		t.Fatalf("VerifyXML returned error: %v", err)
	}
}

func TestVerifyXMLPreservesNonUTF8Input(t *testing.T) {
	document := []byte(`<?xml version="1.0" encoding="windows-1251"?><document>`)
	document = append(document, 0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2) // "Привет" in Windows-1251.
	document = append(document, []byte(`</document>`)...)

	client := &Client{library: &fakeNative{
		verifyXMLFunc: func(_ string, _ ckalkan.Flag, input []byte) (string, error) {
			if !sameByteSliceBacking(input, document) {
				t.Fatal("VerifyXML copied or transcoded the caller's XML buffer")
			}

			return "Verify - OK", nil
		},
	}}

	if _, err := client.VerifyXML(context.Background(), VerifyXMLRequest{XML: Bytes(document)}); err != nil {
		t.Fatalf("VerifyXML returned error: %v", err)
	}
}

func TestVerifyXMLRejectsNestedSignedInfo(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)
	if err := client.LoadKeyStore(ctx, KeyStore{
		Type:     PKCS12,
		Path:     keyStorePath(t, assets),
		Password: fixturePassword,
	}); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}

	unsigned := []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><soap:Header/><soap:Body wsu:Id="TheBody"><payload Id="Other">authentic content</payload></soap:Body></soap:Envelope>`)
	signed, err := client.SignXML(ctx, SignXMLRequest{
		XML:                  Bytes(unsigned),
		SignNodeID:           "Other",
		Canonicalization:     XMLCanonicalizationInclusive,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignXML(#Other) failed: %v", err)
	}
	if !bytes.Contains(signed.XML, []byte(`URI="#Other"`)) {
		t.Fatal(`SignXML output does not reference #Other`)
	}

	decoy := []byte(`<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#TheBody"/></ds:SignedInfo></ds:Object>`)
	signatureEnd := []byte(`</ds:Signature>`)
	if bytes.Count(signed.XML, signatureEnd) != 1 {
		t.Fatalf("SignXML output does not contain one %s closing tag", signatureEnd)
	}
	wrappingDocument := bytes.Replace(signed.XML, signatureEnd, append(decoy, signatureEnd...), 1)

	_, err = client.VerifyXML(ctx, VerifyXMLRequest{
		XML:                  Bytes(wrappingDocument),
		ExpectedBodyID:       "TheBody",
		Canonicalization:     XMLCanonicalizationInclusive,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "exactly one ds:SignedInfo") {
		t.Fatalf("root VerifyXML error = %v, want structural SignedInfo rejection", err)
	}
}
