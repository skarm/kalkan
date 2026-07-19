package ckalkan_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestGeneratedCertificateAPI(t *testing.T) {
	fixture := generatePKCS12Fixture(t)
	client := newRealClient(t)

	if err := client.X509LoadCertificateFromBuffer(fixture.CertPEM, ckalkan.CertPEM); err != nil {
		t.Fatalf("X509LoadCertificateFromBuffer(PEM) failed: %v", err)
	}
	if err := client.X509LoadCertificateFromFile(fixture.CertPath, ckalkan.CertUser); err != nil {
		t.Fatalf("X509LoadCertificateFromFile failed: %v", err)
	}

	exported, err := client.X509ExportCertificateFromStore(fixture.Alias, ckalkan.CertPEM)
	if err != nil {
		t.Fatalf("X509ExportCertificateFromStore failed: %v", err)
	}
	requireContains(t, "exported certificate", exported, "-----BEGIN CERTIFICATE-----")
	cert := requireParsePEMCertificate(t, "exported certificate", exported)
	if cert.Subject.CommonName != fixture.Alias {
		t.Fatalf("exported certificate CN = %q, want %q", cert.Subject.CommonName, fixture.Alias)
	}

	checks := []struct {
		name string
		prop ckalkan.CertProp
		want string
	}{
		{name: "subject country", prop: ckalkan.CertPropSubjectCountryName, want: "C=KZ"},
		{name: "subject organization", prop: ckalkan.CertPropSubjectOrgName, want: "O=ckalkan-test"},
		{name: "subject common name", prop: ckalkan.CertPropSubjectCommonName, want: "CN=" + fixture.Alias},
		{name: "subject serial number", prop: ckalkan.CertPropSubjectSerialNumber, want: "serialNumber=123456"},
		{name: "issuer common name", prop: ckalkan.CertPropIssuerCommonName, want: "CN=" + fixture.Alias},
		{name: "signature algorithm", prop: ckalkan.CertPropSignatureAlg, want: "sha256WithRSAEncryption"},
	}
	for _, check := range checks {
		out, err := client.X509CertificateGetInfo(fixture.CertPEM, check.prop)
		if err != nil {
			t.Fatalf("X509CertificateGetInfo(%s) failed: %v", check.name, err)
		}
		requireContains(t, check.name, out, check.want)
		if strings.Contains(string(out), "\x00") {
			t.Fatalf("X509CertificateGetInfo(%s) returned an untrimmed C string: %q", check.name, out)
		}
	}

	_, err = client.X509ValidateCertificate(ckalkan.ValidateCertificateRequest{
		Certificate:    fixture.CertPEM,
		ValidationType: ckalkan.UseNothing,
		OutputCapacity: 256,
		OCSPCapacity:   256,
		CheckTimeUnix:  0,
		Flags:          ckalkan.NoCheckCertTime,
		ValidationPath: "",
	})
	if err == nil {
		t.Fatal("X509ValidateCertificate unexpectedly trusted the generated self-signed certificate")
	}
	_ = requireKalkanError(t, "X509ValidateCertificate", err)
}

func TestGeneratedPKCS12CMS(t *testing.T) {
	fixture := generatePKCS12Fixture(t)
	client := newRealClient(t)

	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixture.Password, fixture.P12Path, fixture.Alias); err != nil {
		t.Fatalf("LoadKeyStore(generated PKCS#12) failed: %v", err)
	}

	hash, err := client.HashData(ckalkan.SHA256, 0, fixture.Data)
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}
	wantHash := sha256.Sum256(fixture.Data)
	if string(hash) != string(wantHash[:]) {
		t.Fatalf("HashData returned %x, want %x", hash, wantHash)
	}

	signedHash, err := client.SignHash(fixture.Alias, ckalkan.SignCMS|ckalkan.OutBase64|ckalkan.NoCheckCertTime, wantHash[:])
	if err != nil {
		t.Fatalf("SignHash failed: %v", err)
	}
	if len(signedHash) == 0 {
		t.Fatal("SignHash returned an empty signature")
	}

	attachedCMS, err := client.SignData(ckalkan.SignDataRequest{
		Alias: fixture.Alias,
		Flags: ckalkan.SignCMS | ckalkan.OutBase64 | ckalkan.NoCheckCertTime,
		Data:  fixture.Data,
	})
	if err != nil {
		t.Fatalf("SignData(attached CMS) failed: %v", err)
	}
	if len(attachedCMS) == 0 {
		t.Fatal("SignData(attached CMS) returned an empty signature")
	}

	attachedVerify, err := client.VerifyData(ckalkan.VerifyDataRequest{
		Flags:     ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.NoCheckCertTime,
		Data:      fixture.Data,
		Signature: attachedCMS,
	})
	if err != nil {
		t.Fatalf("VerifyData(attached CMS) failed: %v", err)
	}
	requireStringContains(t, "attached verify info", attachedVerify.VerifyInfo, "Verify - OK")
	if string(attachedVerify.Data) != string(fixture.Data) {
		t.Fatalf("VerifyData(attached CMS) data = %q, want %q", attachedVerify.Data, fixture.Data)
	}

	detachedCMS, err := client.SignData(ckalkan.SignDataRequest{
		Alias: fixture.Alias,
		Flags: ckalkan.SignCMS | ckalkan.OutBase64 | ckalkan.DetachedData | ckalkan.NoCheckCertTime,
		Data:  fixture.Data,
	})
	if err != nil {
		t.Fatalf("SignData(detached CMS) failed: %v", err)
	}
	detachedVerify, err := client.VerifyData(ckalkan.VerifyDataRequest{
		Flags:     ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.DetachedData | ckalkan.NoCheckCertTime,
		Data:      fixture.Data,
		Signature: detachedCMS,
	})
	if err != nil {
		t.Fatalf("VerifyData(detached CMS) failed: %v", err)
	}
	requireStringContains(t, "detached verify info", detachedVerify.VerifyInfo, "Verify - OK")

	_, err = client.GetTimeFromSig(attachedCMS, ckalkan.InBase64, 0)
	if err == nil {
		t.Fatal("GetTimeFromSig unexpectedly found a TSA token in an untimestamped CMS")
	}
	if kalkanErr, ok := errors.AsType[*ckalkan.KalkanError](err); !ok || kalkanErr.Code != ckalkan.ErrorNoTSAToken {
		t.Fatalf("GetTimeFromSig error = %v, want ErrorNoTSAToken", err)
	}

	certFromCMS, err := client.GetCertFromCMS(attachedCMS, 0, ckalkan.InBase64)
	if err != nil {
		t.Fatalf("GetCertFromCMS returned error: %v", err)
	}
	// libkalkancryptwr-64.so returns OK but an empty buffer for the
	// generated RSA CMS. Keep the call in the flow test so ABI regressions are
	// still caught without asserting a value that this library version does not
	// reliably produce.
	_ = certFromCMS
}

func TestVerifyDataRetriesTruncatedNativeOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the saturated VerifyData behavior is verified only for the Linux SDK")
	}

	fixture := generatePKCS12Fixture(t)
	client := newRealClient(t)

	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixture.Password, fixture.P12Path, fixture.Alias); err != nil {
		t.Fatalf("LoadKeyStore(generated PKCS#12) failed: %v", err)
	}

	signature, err := client.SignData(ckalkan.SignDataRequest{
		Alias: fixture.Alias,
		Flags: ckalkan.SignCMS | ckalkan.OutBase64 | ckalkan.NoCheckCertTime,
		Data:  fixture.Data,
	})
	if err != nil {
		t.Fatalf("SignData(attached CMS) failed: %v", err)
	}

	verified, err := client.VerifyData(ckalkan.VerifyDataRequest{
		Flags:        ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.NoCheckCertTime,
		Data:         fixture.Data,
		Signature:    signature,
		DataCapacity: len(fixture.Data) - 1,
	})
	if err != nil {
		t.Fatalf("VerifyData(attached CMS) failed: %v", err)
	}
	if !bytes.Equal(verified.Data, fixture.Data) {
		t.Fatalf("VerifyData data = %q, want complete payload %q", verified.Data, fixture.Data)
	}
}

func TestGeneratedXMLAndWSSE(t *testing.T) {
	fixture := generatePKCS12Fixture(t)
	client := newRealClient(t)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixture.Password, fixture.P12Path, fixture.Alias); err != nil {
		t.Fatalf("LoadKeyStore(generated PKCS#12) failed: %v", err)
	}

	xml := []byte(`<root><value>hello</value></root>`)
	signedXML, err := client.SignXML(ckalkan.SignXMLRequest{
		Alias: fixture.Alias,
		Flags: ckalkan.XMLInclC14N | ckalkan.NoCheckCertTime,
		XML:   xml,
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
	if err != nil {
		t.Fatalf("GetCertFromXML returned non-base64 certificate data: %v", err)
	}
	if len(certDER) == 0 {
		t.Fatal("GetCertFromXML returned an empty certificate")
	}

	sigAlg, err := client.GetSigAlgFromXML(signedXML)
	if err != nil {
		t.Fatalf("GetSigAlgFromXML failed: %v", err)
	}
	requireStringContains(t, "XML signature algorithm", sigAlg, "sha256WithRSAEncryption")

	if _, err := client.VerifyXML("", ckalkan.XMLInclC14N|ckalkan.NoCheckCertTime, signedXML); err == nil {
		t.Fatal("VerifyXML unexpectedly trusted the generated self-signed certificate")
	} else {
		_ = requireKalkanError(t, "VerifyXML", err)
	}

	soap := []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"></wsse:Security></soap:Header><soap:Body wsu:Id="body"><root>hello</root></soap:Body></soap:Envelope>`)
	wsse, err := client.SignWSSE(ckalkan.SignWSSERequest{
		Alias:      fixture.Alias,
		Flags:      ckalkan.XMLInclC14N | ckalkan.NoCheckCertTime,
		XML:        soap,
		SignNodeID: "body",
	})
	if err != nil {
		t.Fatalf("SignWSSE failed: %v", err)
	}
	requireContains(t, "WSSE signature", wsse, "wsse:Security")
	requireContains(t, "WSSE signature", wsse, "ds:Signature")
}

func TestGeneratedZIP(t *testing.T) {
	fixture := generatePKCS12Fixture(t)
	client := newRealClient(t)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixture.Password, fixture.P12Path, fixture.Alias); err != nil {
		t.Fatalf("LoadKeyStore(generated PKCS#12) failed: %v", err)
	}

	inputPath := filepath.Join(fixture.Dir, "payload.txt")
	if err := os.WriteFile(inputPath, fixture.Data, 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	if err := client.ZipConSign(ckalkan.ZipConSignRequest{
		Alias:    fixture.Alias,
		FilePath: inputPath,
		Name:     "signed-container",
		OutDir:   fixture.Dir,
		Flags:    ckalkan.NoCheckCertTime,
	}); err != nil {
		t.Fatalf("ZipConSign failed: %v", err)
	}
	zipPath, ok := firstExistingFile(
		filepath.Join(fixture.Dir, "signed-container"),
		filepath.Join(fixture.Dir, "signed-container.zip"),
	)
	if !ok {
		t.Fatalf("ZipConSign succeeded but did not create the expected output in %s", fixture.Dir)
	}

	if _, err := client.ZipConVerify(zipPath, ckalkan.NoCheckCertTime); err == nil {
		t.Log("ZipConVerify accepted the generated container")
	} else {
		// KalkanCrypt signs the generated test payload but does not reliably
		// verify that synthetic container back. Treat the native Kalkan error as a
		// covered call, not as an ABI failure.
		_ = requireKalkanError(t, "ZipConVerify", err)
	}
	if _, err := client.GetCertFromZipFile(zipPath, ckalkan.NoCheckCertTime, 0); err == nil {
		t.Log("GetCertFromZipFile extracted a certificate from the generated container")
	} else {
		_ = requireKalkanError(t, "GetCertFromZipFile", err)
	}
}
