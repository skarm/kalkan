package ckalkan_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestVerifyDataSmallBuffers(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("small-buffer SDK behavior is verified on Linux")
	}
	const payload = "small native output buffers must preserve the complete attached payload"
	if selected := os.Getenv("KALKAN_TEST_VERIFY_BUFFER_CASE"); selected != "" {
		var options []ckalkan.Option
		if selected == "limit" {
			options = append(options, ckalkan.WithMaxBufferSize(1))
		}
		client := newIntegrationClient(t, options...)
		signed, err := os.ReadFile(os.Getenv("KALKAN_TEST_VERIFY_CMS"))
		if err != nil {
			t.Fatal(err)
		}
		request := ckalkan.VerifyDataRequest{
			Flags:     ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime,
			Signature: signed,
			CertID:    1,
		}
		if strings.Contains(selected, "data") {
			request.DataCapacity = 1
		}
		if strings.Contains(selected, "info") {
			request.VerifyInfoCapacity = 1
		}
		if strings.Contains(selected, "cert") {
			request.CertCapacity = 1
		}
		verified, err := client.VerifyData(request)
		if selected == "limit" {
			var limit *ckalkan.OutputBufferLimitError
			if !errors.As(err, &limit) || limit.Limit != 1 || verified.Data != nil || verified.Cert != nil || verified.VerifyInfo != "" {
				t.Fatalf("VerifyData under hard limit = %+v, %v, want typed limit error without output", verified, err)
			}
			return
		}
		certificate, readErr := os.ReadFile(os.Getenv("KALKAN_TEST_VERIFY_CMS") + ".cert")
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err != nil || string(verified.Data) != payload || !strings.Contains(verified.VerifyInfo, "Verify - OK") || !bytes.Equal(verified.Cert, certificate) {
			t.Fatalf("VerifyData(%s) = %+v, %v, want complete verified data", selected, verified, err)
		}
		return
	}

	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)
	assets := loadFixtureAssets(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []struct{ name, password, store string }{
		{name: "RSA", password: fixture.Password, store: fixture.P12Path},
		{name: "GOST", password: fixturePassword, store: chooseStore(t, assets.P12)},
	} {
		t.Run(profile.name, func(t *testing.T) {
			if err := client.LoadKeyStore(ckalkan.StorePKCS12, profile.password, profile.store, ""); err != nil {
				t.Fatal(err)
			}
			signed, err := client.SignData(ckalkan.SignDataRequest{
				Flags: ckalkan.SignCMS | ckalkan.OutDER | ckalkan.WithCert | ckalkan.NoCheckCertTime,
				Data:  []byte(payload),
			})
			if err != nil {
				t.Fatal(err)
			}
			control, err := client.VerifyData(ckalkan.VerifyDataRequest{
				Flags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime, Signature: signed, CertID: 1,
			})
			if err != nil || string(control.Data) != payload || !strings.Contains(control.VerifyInfo, "Verify - OK") || len(control.Cert) == 0 {
				t.Fatalf("positive control = %+v, %v", control, err)
			}
			path := filepath.Join(t.TempDir(), "signed.der")
			if err := os.WriteFile(path, signed, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".cert", control.Cert, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, selected := range []string{"data", "info", "cert", "data-info", "data-cert", "info-cert", "data-info-cert", "limit"} {
				t.Run(selected, func(t *testing.T) {
					// A native overrun must fail only this child, preserving the rest of
					// the suite and the positive control in the parent.
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, executable, "-test.run=^TestVerifyDataSmallBuffers$", "-test.v")
					command.Env = append(os.Environ(), "KALKAN_TEST_VERIFY_BUFFER_CASE="+selected, "KALKAN_TEST_VERIFY_CMS="+path)
					if output, err := command.CombinedOutput(); err != nil {
						t.Fatalf("small-buffer subprocess: %v\n%s", err, output)
					}
				})
			}
		})
	}
}

func TestVerifyDataRejectsTamperedSignerSignature(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the native last-error fallback is verified only for the Linux SDK")
	}
	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)
	assets := loadFixtureAssets(t)
	payload := []byte("native signer-signature validation")
	for _, profile := range []struct{ name, password, store string }{
		{name: "RSA", password: fixture.Password, store: fixture.P12Path},
		{name: "GOST", password: fixturePassword, store: chooseStore(t, assets.P12)},
	} {
		if err := client.LoadKeyStore(ckalkan.StorePKCS12, profile.password, profile.store, ""); err != nil {
			t.Fatal(err)
		}
		for _, detached := range []bool{false, true} {
			flags := ckalkan.SignCMS | ckalkan.NoCheckCertTime
			if detached {
				flags |= ckalkan.DetachedData
			}
			signed, err := client.SignData(ckalkan.SignDataRequest{Flags: flags | ckalkan.OutDER | ckalkan.WithCert, Data: payload})
			if err != nil {
				t.Fatal(err)
			}
			tampered := tamperEmptyCMSSignature(t, signed)
			for _, format := range []struct {
				name   string
				flag   ckalkan.Flag
				encode func([]byte) []byte
			}{
				{name: "DER", flag: ckalkan.InDER, encode: func(data []byte) []byte { return data }},
				{name: "PEM", flag: ckalkan.InPEM, encode: func(data []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: data}) }},
				{name: "Base64", flag: ckalkan.InBase64, encode: func(data []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(data)) }},
			} {
				t.Run(fmt.Sprintf("%s/detached_%v/%s", profile.name, detached, format.name), func(t *testing.T) {
					request := ckalkan.VerifyDataRequest{Flags: flags | format.flag, Data: payload, Signature: format.encode(signed)}
					result, err := client.VerifyData(request)
					if err != nil || !strings.Contains(result.VerifyInfo, "Verify - OK") {
						t.Fatalf("valid CMS = %+v, %v, want successful positive control", result, err)
					}
					request.Signature = format.encode(tampered)
					_, err = client.VerifyData(request)
					requireKalkanError(t, "VerifyData(tampered signer signature)", err)
					// A new verification must clear the preceding signature error.
					request.Signature = format.encode(signed)
					if _, err := client.VerifyData(request); err != nil {
						t.Fatalf("valid CMS after failure: %v", err)
					}
				})
			}
		}
	}
}

func TestEmptyAttachedCMSRemainsRejected(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the negative empty-content output length is verified only for the Linux SDK")
	}
	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixture.Password, fixture.P12Path, fixture.Alias); err != nil {
		t.Fatal(err)
	}
	signed, err := client.SignData(ckalkan.SignDataRequest{Alias: fixture.Alias, Flags: ckalkan.SignCMS | ckalkan.OutDER | ckalkan.WithCert | ckalkan.NoCheckCertTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{name: "valid signature", data: signed, valid: true},
		{name: "tampered signer signature", data: tamperEmptyCMSSignature(t, signed)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "signed.der")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, opensslErr := exec.CommandContext(ctx, requireOpenSSL(t), "cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", path).CombinedOutput()
			if (opensslErr == nil) != test.valid {
				t.Fatalf("OpenSSL validation = %v, want valid=%v: %s", opensslErr, test.valid, out)
			}
			_, err := client.VerifyData(ckalkan.VerifyDataRequest{Flags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime, Signature: test.data})
			if test.valid {
				// Valid empty content remains unsupported because the SDK reports
				// the negative output length -1. Do not normalize that length.
				if err == nil || !strings.Contains(err.Error(), "negative") {
					t.Fatalf("VerifyData = %v, want negative-length rejection of unsupported empty CMS", err)
				}
			} else {
				requireKalkanError(t, "VerifyData(tampered empty CMS)", err)
			}
		})
	}
}

func tamperEmptyCMSSignature(t *testing.T, der []byte) []byte {
	t.Helper()
	var envelope struct {
		OID     asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &envelope); err != nil {
		t.Fatal(err)
	}
	var signed struct {
		Version      int
		Digests      asn1.RawValue
		Content      asn1.RawValue
		Certificates asn1.RawValue   `asn1:"optional,tag:0"`
		Revocations  asn1.RawValue   `asn1:"optional,tag:1"`
		Signers      []asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(envelope.Content.Bytes, &signed); err != nil || len(signed.Signers) != 1 {
		t.Fatalf("decode CMS signer: %v", err)
	}
	var signer struct {
		Version    int
		Identifier asn1.RawValue
		Digest     asn1.RawValue
		Attributes asn1.RawValue `asn1:"optional,tag:0"`
		Algorithm  asn1.RawValue
		Signature  []byte
	}
	if _, err := asn1.Unmarshal(signed.Signers[0].FullBytes, &signer); err != nil {
		t.Fatal(err)
	}
	if len(signer.Signature) == 0 || bytes.Count(der, signer.Signature) != 1 {
		t.Fatal("generated CMS must contain one unambiguous signature value")
	}
	result := bytes.Clone(der)
	result[bytes.Index(result, signer.Signature)+len(signer.Signature)/2] ^= 1
	return result
}

func TestGeneratedCertificateAPI(t *testing.T) {
	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)

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
	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)

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

	certFromCMS, err := client.GetCertFromCMS(attachedCMS, 1, ckalkan.InBase64|ckalkan.OutDER)
	if err != nil {
		t.Fatalf("GetCertFromCMS returned error: %v", err)
	}
	if _, err := x509.ParseCertificate(certFromCMS); err != nil {
		t.Fatalf("GetCertFromCMS returned invalid signer certificate: %v", err)
	}
}

func TestVerifyDataRetriesTruncatedNativeOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the saturated VerifyData behavior is verified only for the Linux SDK")
	}

	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)

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
	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)
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
	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixture.Password, fixture.P12Path, fixture.Alias); err != nil {
		t.Fatalf("LoadKeyStore(generated PKCS#12) failed: %v", err)
	}

	inputDir := t.TempDir()
	inputPath := filepath.Join(inputDir, "payload.txt")
	if err := os.WriteFile(inputPath, fixture.Data, 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	if err := client.ZipConSign(ckalkan.ZipConSignRequest{
		Alias:    fixture.Alias,
		FilePath: inputDir,
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

	info, err := client.ZipConVerify(zipPath, ckalkan.NoCheckCertTime)
	if err != nil {
		t.Fatalf("ZipConVerify(generated container): %v", err)
	}
	requireStringContains(t, "generated ZIP verification", info, "Verify - OK")
	if _, err := client.GetCertFromZipFile(zipPath, ckalkan.NoCheckCertTime, 0); err == nil {
		t.Log("GetCertFromZipFile extracted a certificate from the generated container")
	} else {
		_ = requireKalkanError(t, "GetCertFromZipFile", err)
	}
}
