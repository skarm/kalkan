//go:build linux && cgo

package kalkancrypt_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestContextXMLAndWSSEMethods(t *testing.T) {
	ctx := openContext(t)
	assets := sdkAssetsForIntegration(t)
	loadSDKCertificates(t, ctx, assets)
	loadPKCS12Fixture(t, ctx)

	xml := readSDKExample(t, assets, "test_xml")
	signedXMLResult, err := ctx.SignXML(kalkancrypt.SignXMLCall{
		Flags:    xmlInclC14N | noCheckCertTime,
		XML:      xml,
		Capacity: 1 << 20,
	})
	signedXML := requireBufferOK(t, "SignXML", signedXMLResult, err)
	if !bytes.Contains(signedXML, []byte("<ds:Signature")) {
		t.Fatalf("SignXML result does not contain ds:Signature: %q", signedXML[:min(len(signedXML), 128)])
	}

	certResult, err := ctx.GetCertFromXML(signedXML, 0, 1<<20)
	certFromXML := requireBufferOK(t, "GetCertFromXML", certResult, err)
	if certDER, err := base64.StdEncoding.AppendDecode(nil, bytes.TrimSpace(certFromXML)); err != nil || len(certDER) == 0 {
		t.Fatalf("GetCertFromXML returned invalid base64 DER, len=%d err=%v", len(certDER), err)
	}

	sigAlgResult, err := ctx.GetSigAlgFromXML(signedXML, 1<<20)
	sigAlg := requireBufferOK(t, "GetSigAlgFromXML", sigAlgResult, err)
	if !bytes.Contains(sigAlg, []byte("GOST")) {
		t.Fatalf("GetSigAlgFromXML = %q, want GOST algorithm", sigAlg)
	}

	verifyResult, err := ctx.VerifyXML("", xmlInclC14N|noCheckCertTime, signedXML, 1<<20)
	if err != nil {
		t.Fatalf("VerifyXML returned Go error: %v", err)
	}
	if verifyResult.Code == kcrOK {
		if !bytes.Contains(verifyResult.Data, []byte("OK")) {
			t.Fatalf("VerifyXML info = %q, want OK", verifyResult.Data)
		}
	} else if len(verifyResult.Data) == 0 {
		t.Fatalf("VerifyXML code = %#x with empty diagnostic info", verifyResult.Code)
	}

	wsseResult, err := ctx.SignWSSE(kalkancrypt.SignWSSECall{
		Flags:      uint64(xmlInclC14N | noCheckCertTime),
		XML:        readSDKExample(t, assets, "test_wsse"),
		SignNodeID: "TheBody",
		Capacity:   1 << 20,
	})
	wsse := requireBufferOK(t, "SignWSSE", wsseResult, err)
	if !bytes.Contains(wsse, []byte("wsse:Security")) || !bytes.Contains(wsse, []byte("ds:Signature")) {
		t.Fatalf("SignWSSE result = %q, want wsse:Security and ds:Signature", wsse[:min(len(wsse), 256)])
	}
}
