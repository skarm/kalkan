package kalkan

import (
	"context"
	"errors"
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
