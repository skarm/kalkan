package kalkan

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func FuzzValidateXMLSOAPBinding(f *testing.F) {
	f.Add([]byte("seed"), uint8(0))
	f.Add([]byte{0, 1, 2, 3}, uint8(2))
	f.Add([]byte("collision"), uint8(6))

	f.Fuzz(func(t *testing.T, idSeed []byte, mutation uint8) {
		if len(idSeed) > 32 {
			t.Skip()
		}

		bodyID := "Body_" + hex.EncodeToString(idSeed)
		document := fuzzSignedSOAP(bodyID, "#"+bodyID, "")
		wantValid := false

		switch mutation % 10 {
		case 0:
			wantValid = true
		case 1:
			document = fuzzSignedSOAP(bodyID, "#Other", "")
		case 2:
			document = fuzzSignedSOAP(bodyID, "#Other", `<ds:Object><ds:SignedInfo><ds:Reference URI="#`+bodyID+`"/></ds:SignedInfo></ds:Object>`)
		case 3:
			document = strings.Replace(document, `</ds:SignedInfo>`, `<ds:Reference URI="#`+bodyID+`"/></ds:SignedInfo>`, 1)
		case 4:
			document = strings.Replace(document, `</soap:Header>`, `<ds:Signature/></soap:Header>`, 1)
		case 5:
			document = strings.Replace(document, `</soap:Envelope>`, `<soap:Body wsu:Id="Other"/></soap:Envelope>`, 1)
		case 6, 7, 8, 9:
			attribute := [...]string{"wsu:Id", "xml:id", "Id", "ID"}[mutation%10-6]
			document = strings.Replace(document, `</soap:Envelope>`, `<extra `+attribute+`="`+bodyID+`"/></soap:Envelope>`, 1)
		}

		err := validateXMLVerificationStructure([]byte(document), bodyID)
		if wantValid {
			if err != nil {
				t.Fatalf("valid SOAP binding rejected: %v", err)
			}
			return
		}

		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("mutation %d error = %v, want ErrInvalidInput", mutation%10, err)
		}
	})
}

func FuzzValidateXMLStructure(f *testing.F) {
	f.Add([]byte(fuzzSignedSOAP("TheBody", "#TheBody", "")))
	f.Add([]byte(validSignedGenericXML()))
	f.Add([]byte(`<!DOCTYPE x SYSTEM "http://127.0.0.1/"><x/>`))
	f.Add([]byte{0, '<', 'x', '>'})

	f.Fuzz(func(t *testing.T, document []byte) {
		if len(document) > 64<<10 {
			t.Skip()
		}

		for _, expectedID := range []string{"", "TheBody"} {
			if err := validateXMLVerificationStructure(document, expectedID); err != nil && !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("structural parser returned an unclassified error: %v", err)
			}
		}
	})
}

func fuzzSignedSOAP(bodyID, referenceURI, signatureExtra string) string {
	return `<soap:Envelope xmlns:soap="` + xmlnsSOAP + `" xmlns:wsu="` + xmlnsWSU + `" xmlns:ds="` + xmlnsDSig + `"><soap:Header><ds:Signature><ds:SignedInfo><ds:Reference URI="` + referenceURI + `"/></ds:SignedInfo>` + signatureExtra + `</ds:Signature></soap:Header><soap:Body wsu:Id="` + bodyID + `"><payload>ok</payload></soap:Body></soap:Envelope>`
}
