package kalkan

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

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
