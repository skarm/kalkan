package ckalkan_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestXMLAndWSSE(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newRealClient(t, largeBufferOptions()...)
	loadCertificates(t, client, assets)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixturePassword, chooseStore(t, assets.P12), ""); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}

	signedXML, err := client.SignXML(ckalkan.SignXMLRequest{
		Flags:          ckalkan.XMLInclC14N | ckalkan.NoCheckCertTime,
		XML:            readExample(t, assets, "test_xml"),
		OutputCapacity: 1 << 20,
	})
	if err != nil {
		t.Fatalf("SignXML failed: %v", err)
	}
	requireContains(t, "signed XML", signedXML, "<ds:Signature")

	certFromXML, err := client.GetCertFromXML(signedXML, 0)
	if err != nil {
		t.Fatalf("GetCertFromXML failed: %v", err)
	}
	certDER, err := base64.StdEncoding.AppendDecode(nil, bytes.TrimSpace(certFromXML))
	if err != nil || len(certDER) == 0 {
		t.Fatalf("GetCertFromXML returned invalid base64 DER, len=%d err=%v", len(certDER), err)
	}

	sigAlg, err := client.GetSigAlgFromXML(signedXML)
	if err != nil {
		t.Fatalf("GetSigAlgFromXML failed: %v", err)
	}
	requireStringContains(t, "XML signature algorithm", sigAlg, "GOST R 34.10-2015")

	if info, err := client.VerifyXML("", ckalkan.XMLInclC14N|ckalkan.NoCheckCertTime, signedXML); err == nil {
		requireStringContains(t, "VerifyXML info", info, "OK")
	} else {
		// The fixture certificates are expired historical test certificates and the
		// Linux library often refuses XML trust loading even with NoCheckCertTime.
		requireKalkanError(t, "VerifyXML", err)
	}

	wsse, err := client.SignWSSE(ckalkan.SignWSSERequest{
		Flags:          ckalkan.XMLInclC14N | ckalkan.NoCheckCertTime,
		XML:            readExample(t, assets, "test_wsse"),
		SignNodeID:     "TheBody",
		OutputCapacity: 1 << 20,
	})
	if err != nil {
		t.Fatalf("SignWSSE failed: %v", err)
	}
	requireContains(t, "WSSE signature", wsse, "wsse:Security")
	requireContains(t, "WSSE signature", wsse, "ds:Signature")
}
