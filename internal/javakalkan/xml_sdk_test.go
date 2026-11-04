package javakalkan_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/skarm/kalkan"
)

func TestJavaXMLRejectsXPointerIDs(t *testing.T) {
	client := javaXMLIntegrationClient(t, true)
	for _, id := range []string{"xpointer(/)", "xpointer(id('other'))"} {
		input := []byte(`<root><requested Id="` + id + `">requested payload</requested><other Id="other">other payload</other></root>`)
		_, err := client.SignXML(t.Context(), kalkan.SignXMLRequest{XML: kalkan.Bytes(input), SignNodeID: id, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
		if !errors.Is(err, kalkan.ErrInvalidInput) {
			t.Fatalf("SignXML accepted ambiguous ID %q: %v", id, err)
		}
	}
}

func TestJavaXMLPreservesExistingSignatures(t *testing.T) {
	client := javaXMLIntegrationClient(t, true)
	first, err := client.SignXML(t.Context(), kalkan.SignXMLRequest{XML: kalkan.Bytes([]byte(`<root>signed payload</root>`)), CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
	if err != nil {
		t.Fatal(err)
	}
	javaXMLVerify(t, client, first.XML, "")
	second, err := client.SignXML(t.Context(), kalkan.SignXMLRequest{XML: kalkan.Bytes(first.XML), CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
	if err != nil {
		if !errors.Is(err, kalkan.ErrJavaUnsupported) {
			t.Fatalf("unsupported append should be identified explicitly: %v", err)
		}
		return
	}
	javaXMLVerify(t, client, second.XML, "")
}

func TestJavaXMLSignerCertificateSelection(t *testing.T) {
	client := javaXMLIntegrationClient(t, true)
	signed, err := client.SignXML(t.Context(), kalkan.SignXMLRequest{XML: kalkan.Bytes([]byte(`<root>signed payload</root>`)), CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
	if err != nil {
		t.Fatal(err)
	}
	original, err := client.GetCertFromXML(t.Context(), kalkan.Bytes(signed.XML))
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := os.ReadFile(fixturePath("certs", "nca_gost2022_test.cer"))
	if err != nil {
		t.Fatal(err)
	}
	issuerCert, err := x509.ParseCertificate(issuer)
	if err != nil {
		t.Fatal(err)
	}
	withChain := bytes.Replace(signed.XML, []byte("<ds:X509Certificate>"), []byte("<ds:X509Certificate>"+base64.StdEncoding.EncodeToString(issuerCert.Raw)+"</ds:X509Certificate><ds:X509Certificate>"), 1)
	javaXMLVerify(t, client, withChain, "")
	selected, err := client.GetCertFromXML(t.Context(), kalkan.Bytes(withChain))
	if err != nil || len(selected) != 1 || !bytes.Equal(selected[0].Raw, original[0].Raw) {
		t.Fatalf("GetCertFromXML selected the issuer instead of signer: %v", err)
	}
	// Metadata extraction does not establish payload integrity. With one
	// certificate it must not require an intact SignatureValue either.
	corruptSignature := bytes.Clone(signed.XML)
	start := bytes.Index(corruptSignature, []byte("<ds:SignatureValue>")) + len("<ds:SignatureValue>")
	for corruptSignature[start] == '\r' || corruptSignature[start] == '\n' || corruptSignature[start] == ' ' {
		start++
	}
	if corruptSignature[start] == 'A' {
		corruptSignature[start] = 'B'
	} else {
		corruptSignature[start] = 'A'
	}
	for _, damaged := range [][]byte{
		bytes.Replace(withChain, []byte("signed payload"), []byte("altered payload"), 1),
		corruptSignature,
	} {
		javaXMLReject(t, client, damaged, "")
		extracted, err := client.GetCertFromXML(t.Context(), kalkan.Bytes(damaged))
		if err != nil || len(extracted) != 1 || !bytes.Equal(extracted[0].Raw, original[0].Raw) {
			t.Fatalf("certificate extraction incorrectly required valid content/signature: %v", err)
		}
	}
}

func TestJavaWSSERejectsSecondSignature(t *testing.T) {
	client := javaXMLIntegrationClient(t, true)
	signed, err := client.SignWSSE(t.Context(), kalkan.SignWSSERequest{XML: kalkan.Bytes([]byte(`<payload>body</payload>`)), BodyID: "body", WrapSOAP: true, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SignWSSE(t.Context(), kalkan.SignWSSERequest{XML: kalkan.Bytes(signed.XML), BodyID: "body", CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}); !errors.Is(err, kalkan.ErrJavaUnsupported) {
		t.Fatalf("SignWSSE must not emit a SOAP document its verifier rejects: %v", err)
	}
}

func javaXMLIntegrationClient(t *testing.T, trusted bool) *kalkan.Client {
	t.Helper()
	if os.Getenv("KALKANCRYPT_JAVA_PROVIDER") == "" || os.Getenv("KALKANCRYPT_JAVA_XML_LIBRARIES") == "" {
		t.Skip("set KALKANCRYPT_JAVA_PROVIDER and KALKANCRYPT_JAVA_XML_LIBRARIES to run Java XML integration tests")
	}
	assets := loadFixtureAssets(t)
	var options []kalkan.Option
	if trusted {
		options = javaIntegrationTrust(t, assets)
	}
	client := openJavaIntegrationClient(t, options...)
	loadJavaIntegrationKeyStore(t, client, assets)
	return client
}

func TestJavaXMLCanonicalization(t *testing.T) {
	client := javaXMLIntegrationClient(t, true)
	ctx := context.Background()
	for _, tc := range []struct {
		mode kalkan.XMLCanonicalization
		uri  string
	}{
		{kalkan.XMLCanonicalizationInclusive, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"},
		{kalkan.XMLCanonicalizationInclusiveWithComments, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"},
		{kalkan.XMLCanonicalizationInclusive11, "http://www.w3.org/2006/12/xml-c14n11"},
		{kalkan.XMLCanonicalizationInclusive11WithComments, "http://www.w3.org/2006/12/xml-c14n11#WithComments"},
		{kalkan.XMLCanonicalizationExclusive, "http://www.w3.org/2001/10/xml-exc-c14n#"},
		{kalkan.XMLCanonicalizationExclusiveWithComments, "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"},
	} {
		t.Run(fmt.Sprint(tc.mode), func(t *testing.T) {
			signed, err := client.SignXML(ctx, kalkan.SignXMLRequest{
				XML:              kalkan.Bytes([]byte(`<root xmlns="urn:java:test"><data>signed payload</data><!-- retained comment --></root>`)),
				Canonicalization: tc.mode, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
			})
			if err != nil {
				t.Fatalf("SignXML: %v", err)
			}
			if !bytes.Contains(signed.XML, []byte(`<ds:CanonicalizationMethod Algorithm="`+tc.uri+`"`)) {
				t.Fatalf("SignedInfo does not use requested canonicalization %q", tc.uri)
			}
			javaXMLVerify(t, client, signed.XML, "")
			certificates, err := client.GetCertFromXML(ctx, kalkan.Bytes(signed.XML))
			if err != nil || len(certificates) != 1 || len(certificates[0].Raw) == 0 {
				t.Fatalf("GetCertFromXML = %v, %v", certificates, err)
			}
			algorithm, err := client.GetSigAlgFromXML(ctx, kalkan.Bytes(signed.XML))
			if err != nil || algorithm != "signatureAlgorithm=GOST R 34.10-2015 with GOST R 34.11-2015 (512 bit)(1.2.398.3.10.1.1.2.3.2)" {
				t.Fatalf("GetSigAlgFromXML = %q, %v", algorithm, err)
			}
			javaXMLReject(t, client, bytes.Replace(signed.XML, []byte("signed payload"), []byte("tampered payload"), 1), "")
			javaXMLVerify(t, client, signed.XML, "")
		})
	}
}

func TestJavaXMLTargetAndParent(t *testing.T) {
	client := javaXMLIntegrationClient(t, true)
	ctx := context.Background()
	request := kalkan.SignXMLRequest{
		XML:        kalkan.Bytes([]byte(`<root xmlns:p="urn:signatures"><data Id="payload">signed value</data><p:signatures/><outside>unsigned value</outside></root>`)),
		SignNodeID: "payload", ParentSignNode: "signatures", ParentNamespace: "urn:signatures", CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
	}
	signed, err := client.SignXML(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(signed.XML))
	var stack []xml.Name
	var found bool
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch element := token.(type) {
		case xml.StartElement:
			if element.Name == (xml.Name{Space: xmlnsDSig, Local: "Signature"}) {
				found = len(stack) == 2 && stack[1] == (xml.Name{Space: "urn:signatures", Local: "signatures"})
			}
			stack = append(stack, element.Name)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
	if !found || !bytes.Contains(signed.XML, []byte(`URI="#payload"`)) {
		t.Fatal("signature did not use the requested target and namespace-qualified parent")
	}
	javaXMLVerify(t, client, signed.XML, "")
	javaXMLVerify(t, client, bytes.Replace(signed.XML, []byte("unsigned value"), []byte("changed outside target"), 1), "")
	javaXMLReject(t, client, bytes.Replace(signed.XML, []byte("signed value"), []byte("changed target"), 1), "")

	for _, input := range []string{
		`<root xmlns:p="urn:signatures"><data Id="payload"/><p:signatures/><p:signatures/></root>`,
		`<root xmlns:p="urn:signatures"><data Id="payload"/><other id="payload"/><p:signatures/></root>`,
		`<root xmlns:p="urn:signatures"><data Id="missing"/><p:signatures/></root>`,
	} {
		request.XML = kalkan.Bytes([]byte(input))
		if _, err := client.SignXML(ctx, request); !errors.Is(err, kalkan.ErrInvalidInput) {
			t.Fatalf("invalid target/parent accepted or incorrectly classified: %v", err)
		}
	}
}

func TestJavaXMLValidationBoundaries(t *testing.T) {
	client := javaXMLIntegrationClient(t, true)
	ctx := context.Background()
	signed, err := client.SignXML(ctx, kalkan.SignXMLRequest{XML: kalkan.Bytes([]byte(`<root><data>signed value</data></root>`)), CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
	if err != nil {
		t.Fatal(err)
	}
	javaXMLVerify(t, client, signed.XML, "")

	for _, tc := range []struct {
		name string
		old  string
		new  string
		want error
	}{
		{"external reference", `URI=""`, `URI="https://xml-reference.invalid/document"`, kalkan.ErrInvalidInput},
		{"XSLT transform", `http://www.w3.org/2000/09/xmldsig#enveloped-signature`, `http://www.w3.org/TR/1999/REC-xslt-19991116`, kalkan.ErrJavaUnsupported},
		{"XML Object", `</ds:Signature>`, `<ds:Object><unsigned>value</unsigned></ds:Object></ds:Signature>`, kalkan.ErrJavaUnsupported},
		{"DTD", `<root>`, `<!DOCTYPE root [<!ENTITY external SYSTEM "file:///etc/passwd">]><root>`, kalkan.ErrInvalidInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := bytes.Replace(signed.XML, []byte(tc.old), []byte(tc.new), 1)
			if bytes.Equal(mutated, signed.XML) {
				t.Fatal("mutation did not change signed XML")
			}
			_, err := client.VerifyXML(ctx, kalkan.VerifyXMLRequest{XML: kalkan.Bytes(mutated), CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyXML = %v, want %v", err, tc.want)
			}
			javaXMLVerify(t, client, signed.XML, "")
		})
	}

	if _, err := client.VerifyXML(ctx, kalkan.VerifyXMLRequest{XML: kalkan.Bytes(signed.XML)}); err == nil {
		t.Fatal("expired historical signer accepted with default certificate time check")
	}
	untrusted := javaXMLIntegrationClient(t, false)
	javaXMLReject(t, untrusted, signed.XML, "")
}

func TestJavaXMLMultipleSignatures(t *testing.T) {
	client := javaXMLIntegrationClient(t, true)
	ctx := context.Background()
	first, err := client.SignXML(ctx, kalkan.SignXMLRequest{
		XML:        kalkan.Bytes([]byte(`<root><first Id="first">first payload</first><second Id="second">second payload</second></root>`)),
		SignNodeID: "first", CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.SignXML(ctx, kalkan.SignXMLRequest{XML: kalkan.Bytes(first.XML), SignNodeID: "second", CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
	if err != nil {
		t.Fatal(err)
	}
	javaXMLVerify(t, client, second.XML, "")
	certificates, err := client.GetCertFromXML(ctx, kalkan.Bytes(second.XML))
	if err != nil || len(certificates) != 2 {
		t.Fatalf("GetCertFromXML multiple signatures = %d, %v", len(certificates), err)
	}
	javaXMLReject(t, client, bytes.Replace(second.XML, []byte("second payload"), []byte("second tampered"), 1), "")
	javaXMLReject(t, client, bytes.Replace(second.XML, []byte("first payload"), []byte("first tampered"), 1), "")
}

func TestJavaWSSE(t *testing.T) {
	client := javaXMLIntegrationClient(t, true)
	ctx := context.Background()
	for _, canonicalization := range []kalkan.XMLCanonicalization{kalkan.XMLCanonicalizationInclusive, kalkan.XMLCanonicalizationExclusive} {
		for _, soapNS := range []string{xmlnsSOAP, xmlnsSOAP12} {
			t.Run(fmt.Sprintf("%d/%s", canonicalization, soapNS), func(t *testing.T) {
				xml := []byte(`<soap:Envelope xmlns:soap="` + soapNS + `" xmlns:wsu="` + xmlnsWSU + `"><soap:Body wsu:Id="body"><payload>soap payload</payload></soap:Body></soap:Envelope>`)
				signed, err := client.SignWSSE(ctx, kalkan.SignWSSERequest{XML: kalkan.Bytes(xml), BodyID: "body", Canonicalization: canonicalization, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
				if err != nil {
					t.Fatal(err)
				}
				javaXMLVerify(t, client, signed.XML, "body")
				certificates, err := client.GetCertFromXML(ctx, kalkan.Bytes(signed.XML))
				if err != nil || len(certificates) != 1 || !bytes.Contains(signed.XML, []byte("wsse:KeyIdentifier")) || !bytes.Contains(signed.XML, []byte("wsse:SecurityTokenReference")) {
					t.Fatalf("WSSE X509 token extraction = %d, %v", len(certificates), err)
				}
				javaXMLReject(t, client, bytes.Replace(signed.XML, []byte("soap payload"), []byte("tampered"), 1), "body")
				javaXMLReject(t, client, signed.XML, "wrong-body")
			})
		}
	}
	wrapped, err := client.SignWSSE(ctx, kalkan.SignWSSERequest{XML: kalkan.Bytes([]byte(`<payload>wrapped payload</payload>`)), BodyID: "wrapped", WrapSOAP: true, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
	if err != nil {
		t.Fatal(err)
	}
	javaXMLVerify(t, client, wrapped.XML, "wrapped")

	// Other WS-Security senders reference a separate BinarySecurityToken. The
	// token layout is outside SignedInfo and the signed Body, so this conversion
	// must preserve cryptographic validity while exercising certificate lookup.
	start := bytes.Index(wrapped.XML, []byte("<wsse:KeyIdentifier"))
	end := bytes.Index(wrapped.XML, []byte("</wsse:KeyIdentifier>"))
	if start < 0 || end < start {
		t.Fatal("WSSE output has no embedded KeyIdentifier")
	}
	content := start + bytes.IndexByte(wrapped.XML[start:], '>') + 1
	certificate := wrapped.XML[content:end]
	identifier := wrapped.XML[start : end+len("</wsse:KeyIdentifier>")]
	token := []byte(`<wsse:BinarySecurityToken xmlns:wsu="` + xmlnsWSU + `" wsu:Id="separate-token" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">` + string(certificate) + `</wsse:BinarySecurityToken>`)
	referenced := bytes.Replace(wrapped.XML, identifier, []byte(`<wsse:Reference URI="#separate-token"/>`), 1)
	referenced = bytes.Replace(referenced, []byte("</wsse:Security>"), append(token, []byte("</wsse:Security>")...), 1)
	javaXMLVerify(t, client, referenced, "wrapped")
	certificates, err := client.GetCertFromXML(ctx, kalkan.Bytes(referenced))
	if err != nil || len(certificates) != 1 {
		t.Fatalf("BinarySecurityToken certificate extraction = %d, %v", len(certificates), err)
	}
	if _, err := client.VerifyXML(ctx, kalkan.VerifyXMLRequest{XML: kalkan.Bytes(wrapped.XML), CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}); !errors.Is(err, kalkan.ErrInvalidInput) {
		t.Fatalf("SOAP verification without expected body accepted: %v", err)
	}
}

func TestJavaXMLNativeFixtures(t *testing.T) {
	client := javaXMLIntegrationClient(t, true)
	for _, kind := range []string{"xml", "wsse"} {
		t.Run(kind, func(t *testing.T) {
			encoded, err := os.ReadFile(fixturePath("java_xml", "native-"+kind+".xml"))
			if err != nil {
				t.Fatal(err)
			}
			bodyID := ""
			if kind == "wsse" {
				bodyID = "body"
			}
			javaXMLVerify(t, client, encoded, bodyID)
			certificates, err := client.GetCertFromXML(t.Context(), kalkan.Bytes(encoded))
			if err != nil || len(certificates) != 1 || certificates[0].SerialNumber.Text(16) != "12c7a21f2df78b99cb67323e2e255779bb6ae309" {
				t.Fatalf("native signer certificate extraction = %v, %v", certificates, err)
			}
			algorithm, err := client.GetSigAlgFromXML(t.Context(), kalkan.Bytes(encoded))
			if err != nil || algorithm != "signatureAlgorithm=GOST R 34.10-2015 with GOST R 34.11-2015 (512 bit)(1.2.398.3.10.1.1.2.3.2)" {
				t.Fatalf("native signature algorithm = %q, %v", algorithm, err)
			}
			tampered := bytes.Replace(encoded, []byte("interoperability"), []byte("tampered"), 1)
			if bytes.Equal(tampered, encoded) {
				t.Fatal("native fixture mutation did not change payload")
			}
			javaXMLReject(t, client, tampered, bodyID)
		})
	}
}

func TestJavaXMLRevocation(t *testing.T) {
	requireJavaValidationProvider(t)
	if os.Getenv("KALKANCRYPT_JAVA_XML_LIBRARIES") == "" {
		t.Skip("set KALKANCRYPT_JAVA_XML_LIBRARIES to run Java XML integration tests")
	}
	var pki *javaValidationPKI
	var crls map[string]map[string][]byte
	var fault atomic.Value
	fault.Store("good")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentFault, _ := fault.Load().(string)
		var response []byte
		switch r.URL.Path {
		case "/ocsp":
			request, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				t.Error(err)
				return
			}
			response, err = pki.ocsp(request, currentFault)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/ocsp-response")
		case "/root.crl", "/intermediate.crl":
			response = crls[currentFault][r.URL.Path]
		default:
			t.Errorf("unexpected XML revocation request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		requests.Add(1)
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)
	pki = newJavaValidationPKI(t, server.URL)
	crls = make(map[string]map[string][]byte)
	for _, fault := range []string{"good", "revoked", "revoked intermediate", "forged signature"} {
		crls[fault] = map[string][]byte{
			"/root.crl": pki.crl(t, pki.root, fault), "/intermediate.crl": pki.crl(t, pki.intermediate, fault),
		}
	}
	keyStore := javaValidationKeyStore(t, pki.leaf)
	for _, mode := range []kalkan.CertificateValidationMode{kalkan.CertificateValidationOCSP, kalkan.CertificateValidationCRL} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			options := append(pki.trust(t), kalkan.WithOCSPURL(server.URL+"/ocsp"), kalkan.WithJavaRevocation(mode, ""))
			client := openJavaClientWithOptions(t, options...)
			if err := client.LoadKeyStore(t.Context(), kalkan.KeyStore{Type: kalkan.PKCS12, Path: keyStore, Password: "test-password"}); err != nil {
				t.Fatal(err)
			}
			signed, err := client.SignXML(t.Context(), kalkan.SignXMLRequest{XML: kalkan.Bytes([]byte(`<root>current RSA XML signer</root>`))})
			if err != nil {
				t.Fatal(err)
			}
			algorithm, err := client.GetSigAlgFromXML(t.Context(), kalkan.Bytes(signed.XML))
			if err != nil || algorithm != "signatureAlgorithm=sha256WithRSAEncryption(1.2.840.113549.1.1.11)" {
				t.Fatalf("RSA XML algorithm = %q, %v", algorithm, err)
			}
			fault.Store("good")
			before := requests.Load()
			javaXMLVerify(t, client, signed.XML, "")
			if requests.Load()-before < 2 {
				t.Fatal("XML verification did not check both leaf and intermediate revocation")
			}
			for _, bad := range []string{"revoked", "revoked intermediate", "forged signature"} {
				fault.Store(bad)
				javaXMLReject(t, client, signed.XML, "")
				fault.Store("good")
				javaXMLVerify(t, client, signed.XML, "")
			}
		})
	}
}

func javaXMLVerify(t *testing.T, client *kalkan.Client, document []byte, bodyID string) {
	t.Helper()
	result, err := client.VerifyXML(context.Background(), kalkan.VerifyXMLRequest{XML: kalkan.Bytes(document), ExpectedBodyID: bodyID, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
	if err != nil || result == nil || !strings.Contains(result.Info, "Verify XML - OK") {
		t.Fatalf("VerifyXML = %#v, %v", result, err)
	}
}

func javaXMLReject(t *testing.T, client *kalkan.Client, document []byte, bodyID string) {
	t.Helper()
	if _, err := client.VerifyXML(context.Background(), kalkan.VerifyXMLRequest{XML: kalkan.Bytes(document), ExpectedBodyID: bodyID, CertificateTimeCheck: kalkan.SkipCertificateTimeCheck}); err == nil {
		t.Fatal("VerifyXML accepted invalid/untrusted XML")
	} else {
		var providerError *kalkan.JavaError
		if !errors.Is(err, kalkan.ErrInvalidInput) && !errors.As(err, &providerError) {
			t.Fatalf("XML validation failed outside the XML verifier: %v", err)
		}
	}
}

const (
	xmlnsSOAP   = "http://schemas.xmlsoap.org/soap/envelope/"
	xmlnsSOAP12 = "http://www.w3.org/2003/05/soap-envelope"
	xmlnsWSU    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	xmlnsDSig   = "http://www.w3.org/2000/09/xmldsig#"
)
