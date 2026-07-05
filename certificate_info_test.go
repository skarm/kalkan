package kalkan

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestX509ExportCertificateFromStoreParsesDERCertificate(t *testing.T) {
	der := testCertificateDER(t, "store-cert")
	native := &fakeNative{
		exportCertStoreFunc: func(alias string, format ckalkan.CertFormat) ([]byte, error) {
			if alias != "" {
				t.Fatalf("alias = %q, want default empty alias", alias)
			}
			if format != ckalkan.CertDER {
				t.Fatalf("format = %#x, want CertDER", format)
			}

			return der, nil
		},
	}
	client := &Client{library: native}

	cert, err := client.X509ExportCertificateFromStore(context.Background())
	if err != nil {
		t.Fatalf("X509ExportCertificateFromStore returned error: %v", err)
	}
	if cert.Subject.CommonName != "store-cert" {
		t.Fatalf("certificate CN = %q, want store-cert", cert.Subject.CommonName)
	}
}

func TestX509CertificateGetInfoBuildsStructuredInfo(t *testing.T) {
	der := testCertificateDER(t, "subject-from-cert")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	wantFrom := time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)
	wantUntil := time.Date(2025, 1, 3, 16, 5, 6, 0, time.UTC)

	native := &fakeNative{
		certificateGetInfoFunc: func(input []byte, prop ckalkan.CertProp) ([]byte, error) {
			block, _ := pem.Decode(input)
			if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, der) {
				t.Fatalf("certificate info input is not PEM for the supplied certificate")
			}

			value, ok := validCertificateInfoProps()[prop]
			if !ok {
				return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
			}

			return []byte(value), nil
		},
	}
	client := &Client{library: native}

	info, err := client.X509CertificateGetInfo(context.Background(), cert)
	if err != nil {
		t.Fatalf("X509CertificateGetInfo returned error: %v", err)
	}

	if info.Subject != "CN = Native Subject" {
		t.Fatalf("Subject = %q", info.Subject)
	}
	if info.SerialNumber != "certificateSerialNumber=010203" {
		t.Fatalf("SerialNumber = %q", info.SerialNumber)
	}
	if !info.ValidFrom.Equal(wantFrom) {
		t.Fatalf("ValidFrom = %s, want %s", info.ValidFrom, wantFrom)
	}
	if !info.ValidUntil.Equal(wantUntil) {
		t.Fatalf("ValidUntil = %s, want %s", info.ValidUntil, wantUntil)
	}
	if info.Issuer != "CN = Native Issuer" {
		t.Fatalf("Issuer = %q", info.Issuer)
	}
	if info.AlgorithmSignCert != "GOST R 34.10-2015" {
		t.Fatalf("AlgorithmSignCert = %q", info.AlgorithmSignCert)
	}
	if info.OCSPURL != "OCSP=http://ocsp.example.test" {
		t.Fatalf("OCSPURL = %q", info.OCSPURL)
	}
	if !reflect.DeepEqual(info.Policies, []string{"1.2.398.3.3.4", "1.2.398.3.3.5"}) {
		t.Fatalf("Policies = %#v", info.Policies)
	}
	if !reflect.DeepEqual(info.KeyUsages, []string{"digitalSignature", "nonRepudiation"}) {
		t.Fatalf("KeyUsages = %#v", info.KeyUsages)
	}
	if !reflect.DeepEqual(info.ExtKeyUsages, []string{"clientAuth", "emailProtection"}) {
		t.Fatalf("ExtKeyUsages = %#v", info.ExtKeyUsages)
	}
}

func TestX509CertificateGetInfoFieldsFetchesOnlyRequestedProperties(t *testing.T) {
	der := testCertificateDER(t, "subject-from-cert")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	var gotProps []ckalkan.CertProp
	native := &fakeNative{
		certificateGetInfoFunc: func(_ []byte, prop ckalkan.CertProp) ([]byte, error) {
			gotProps = append(gotProps, prop)
			switch prop {
			case ckalkan.CertPropSubjectDN:
				return []byte("CN = Native Subject"), nil
			case ckalkan.CertPropCertSN:
				return []byte("certificateSerialNumber=010203"), nil
			default:
				t.Fatalf("unexpected certificate property %#x", prop)
				return nil, nil
			}
		},
	}
	client := &Client{library: native}

	info, err := client.X509CertificateGetInfoFields(context.Background(), cert, CertificateInfoSubject|CertificateInfoSerialNumber)
	if err != nil {
		t.Fatalf("X509CertificateGetInfoFields returned error: %v", err)
	}

	if !reflect.DeepEqual(gotProps, []ckalkan.CertProp{ckalkan.CertPropSubjectDN, ckalkan.CertPropCertSN}) {
		t.Fatalf("certificate properties = %#v, want subject and serial only", gotProps)
	}
	if info.Subject != "CN = Native Subject" {
		t.Fatalf("Subject = %q", info.Subject)
	}
	if info.SerialNumber != "certificateSerialNumber=010203" {
		t.Fatalf("SerialNumber = %q", info.SerialNumber)
	}
	if !info.ValidFrom.IsZero() || info.Issuer != "" || len(info.Policies) != 0 {
		t.Fatalf("unrequested fields were populated: %+v", info)
	}
}

func TestX509CertificateGetInfoReturnsRequiredPropertyErrors(t *testing.T) {
	der := testCertificateDER(t, "subject-from-cert")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	tests := []struct {
		name string
		prop ckalkan.CertProp
	}{
		{name: "subject", prop: ckalkan.CertPropSubjectDN},
		{name: "serial_number", prop: ckalkan.CertPropCertSN},
		{name: "valid_from", prop: ckalkan.CertPropNotBefore},
		{name: "valid_until", prop: ckalkan.CertPropNotAfter},
		{name: "issuer", prop: ckalkan.CertPropIssuerDN},
		{name: "policy", prop: ckalkan.CertPropPoliciesID},
		{name: "key_usage", prop: ckalkan.CertPropKeyUsage},
		{name: "extended_key_usage", prop: ckalkan.CertPropExtKeyUsage},
		{name: "authority_key_id", prop: ckalkan.CertPropAuthKeyID},
		{name: "subject_key_id", prop: ckalkan.CertPropSubjKeyID},
		{name: "signature_algorithm", prop: ckalkan.CertPropSignatureAlg},
		{name: "public_key", prop: ckalkan.CertPropPubKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			props := validCertificateInfoProps()
			native := &fakeNative{
				certificateGetInfoFunc: func(_ []byte, prop ckalkan.CertProp) ([]byte, error) {
					if prop == tt.prop {
						return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
					}

					value, ok := props[prop]
					if !ok {
						t.Fatalf("unexpected certificate property %#x", prop)
					}

					return []byte(value), nil
				},
			}
			client := &Client{library: native}

			_, err = client.X509CertificateGetInfo(context.Background(), cert)
			requireKalkanErrorCode(t, err, ckalkan.ErrorGetCertProp)
		})
	}
}

func TestX509CertificateGetInfoIgnoresOptionalPropertyErrors(t *testing.T) {
	der := testCertificateDER(t, "subject-from-cert")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}

	tests := []struct {
		name  string
		prop  ckalkan.CertProp
		field func(*CertificateInfo) string
	}{
		{name: "ocsp", prop: ckalkan.CertPropOCSP, field: func(info *CertificateInfo) string {
			return info.OCSPURL
		}},
		{name: "crl", prop: ckalkan.CertPropGetCRL, field: func(info *CertificateInfo) string {
			return info.CRLURL
		}},
		{name: "delta_crl", prop: ckalkan.CertPropGetDeltaCRL, field: func(info *CertificateInfo) string {
			return info.DeltaCRLURL
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			props := validCertificateInfoProps()
			native := &fakeNative{
				certificateGetInfoFunc: func(_ []byte, prop ckalkan.CertProp) ([]byte, error) {
					if prop == tt.prop {
						return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
					}

					value, ok := props[prop]
					if !ok {
						t.Fatalf("unexpected certificate property %#x", prop)
					}

					return []byte(value), nil
				},
			}
			client := &Client{library: native}

			info, err := client.X509CertificateGetInfo(context.Background(), cert)
			if err != nil {
				t.Fatalf("X509CertificateGetInfo returned error: %v", err)
			}
			if got := tt.field(info); got != "" {
				t.Fatalf("optional field = %q, want empty", got)
			}
			if info.Subject != "CN = Native Subject" {
				t.Fatalf("Subject = %q", info.Subject)
			}
		})
	}
}

func TestGetCertFromCMSExtractsAllSignerCertificates(t *testing.T) {
	firstDER := testCertificateDER(t, "cms-signer-0")
	secondDER := testCertificateDER(t, "cms-signer-1")
	var signIDs []int

	native := &fakeNative{
		getCertFromCMSFunc: func(cms []byte, signID int, flags ckalkan.Flag) ([]byte, error) {
			if string(cms) != "cms-base64" {
				t.Fatalf("CMS input = %q, want cms-base64", cms)
			}
			wantFlags := ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.OutBase64
			if flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, wantFlags)
			}

			signIDs = append(signIDs, signID)
			switch signID {
			case 0:
				return []byte(base64.StdEncoding.EncodeToString(firstDER)), nil
			case 1:
				return secondDER, nil
			default:
				return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound}
			}
		},
	}
	client := &Client{library: native}

	certs, err := client.GetCertFromCMS(context.Background(), Base64([]byte("cms-base64")))
	if err != nil {
		t.Fatalf("GetCertFromCMS returned error: %v", err)
	}
	if !reflect.DeepEqual(signIDs, []int{0, 1, 2}) {
		t.Fatalf("signIDs = %#v", signIDs)
	}
	if len(certs) != 2 {
		t.Fatalf("cert count = %d, want 2", len(certs))
	}
	if certs[0].Subject.CommonName != "cms-signer-0" || certs[1].Subject.CommonName != "cms-signer-1" {
		t.Fatalf("cert CNs = %q/%q", certs[0].Subject.CommonName, certs[1].Subject.CommonName)
	}
}

func TestGetCertFromXMLExtractsAllSignerCertificates(t *testing.T) {
	der := testCertificateDER(t, "xml-signer")
	var signIDs []int

	native := &fakeNative{
		getCertFromXMLFunc: func(xml []byte, signID int) ([]byte, error) {
			if string(xml) != "<root/>" {
				t.Fatalf("XML input = %q, want <root/>", xml)
			}

			signIDs = append(signIDs, signID)
			if signID == 0 {
				return []byte(base64.StdEncoding.EncodeToString(der)), nil
			}

			return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound}
		},
	}
	client := &Client{library: native}

	certs, err := client.GetCertFromXML(context.Background(), Bytes([]byte("<root/>")))
	if err != nil {
		t.Fatalf("GetCertFromXML returned error: %v", err)
	}
	if !reflect.DeepEqual(signIDs, []int{0, 1}) {
		t.Fatalf("signIDs = %#v", signIDs)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "xml-signer" {
		t.Fatalf("certs = %#v", certs)
	}
}

func TestGetCertFromSignedDataReturnsFirstCertNotFoundError(t *testing.T) {
	tests := []struct {
		name    string
		library func(*testing.T) *fakeNative
		call    func(*Client) error
	}{
		{
			name: "CMS",
			library: func(t *testing.T) *fakeNative {
				t.Helper()

				return &fakeNative{
					getCertFromCMSFunc: func(_ []byte, signID int, _ ckalkan.Flag) ([]byte, error) {
						if signID != 0 {
							t.Fatalf("signID = %d, want 0", signID)
						}

						return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound}
					},
				}
			},
			call: func(client *Client) error {
				_, err := client.GetCertFromCMS(context.Background(), Base64([]byte("cms-base64")))
				return err
			},
		},
		{
			name: "XML",
			library: func(t *testing.T) *fakeNative {
				t.Helper()

				return &fakeNative{
					getCertFromXMLFunc: func(_ []byte, signID int) ([]byte, error) {
						if signID != 0 {
							t.Fatalf("signID = %d, want 0", signID)
						}

						return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound}
					},
				}
			},
			call: func(client *Client) error {
				_, err := client.GetCertFromXML(context.Background(), Bytes([]byte("<root/>")))
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{library: tt.library(t)}

			err := tt.call(client)
			requireKalkanErrorCode(t, err, ckalkan.ErrorCertNotFound)
		})
	}
}

func TestGetSigAlgFromXMLUsesXMLInput(t *testing.T) {
	native := &fakeNative{
		getSigAlgFromXMLFunc: func(xml []byte) (string, error) {
			if string(xml) != "<signed/>" {
				t.Fatalf("XML input = %q, want <signed/>", xml)
			}

			return "urn:test:signature-algorithm", nil
		},
	}
	client := &Client{library: native}

	algorithm, err := client.GetSigAlgFromXML(context.Background(), Bytes([]byte("<signed/>")))
	if err != nil {
		t.Fatalf("GetSigAlgFromXML returned error: %v", err)
	}
	if algorithm != "urn:test:signature-algorithm" {
		t.Fatalf("algorithm = %q", algorithm)
	}
}

func TestGetTimeFromSigUsesSignatureEncoding(t *testing.T) {
	want := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)
	native := &fakeNative{
		getTimeFromSigFunc: func(data []byte, flags ckalkan.Flag, sigID int) (time.Time, error) {
			if string(data) != "raw-cms" {
				t.Fatalf("signature input = %q, want raw-cms", data)
			}
			if flags != ckalkan.InDER {
				t.Fatalf("flags = %#x, want InDER", flags)
			}
			if sigID != 0 {
				t.Fatalf("sigID = %d, want 0", sigID)
			}

			return want, nil
		},
	}
	client := &Client{library: native}

	got, err := client.GetTimeFromSig(context.Background(), Bytes([]byte("raw-cms")))
	if err != nil {
		t.Fatalf("GetTimeFromSig returned error: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("time = %s, want %s", got, want)
	}
}

func TestSetProxyValidatesAndCallsNative(t *testing.T) {
	native := &fakeNative{
		setProxyFunc: func(req ckalkan.ProxyRequest) error {
			wantFlags := ckalkan.ProxyOn | ckalkan.ProxyAuth
			if req.Flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", req.Flags, wantFlags)
			}
			if req.Address != "127.0.0.1" || req.Port != "3128" {
				t.Fatalf("proxy address/port = %q/%q", req.Address, req.Port)
			}
			if req.User != "user" || req.Password != "password" {
				t.Fatalf("proxy credentials = %q/%q", req.User, req.Password)
			}

			return nil
		},
	}
	client := &Client{library: native}

	err := client.SetProxy(context.Background(), Proxy{
		Enabled:  true,
		Address:  " 127.0.0.1 ",
		Port:     " 3128 ",
		User:     "user",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("SetProxy returned error: %v", err)
	}
}

func TestSetProxyRejectsInvalidProxyBeforeNativeCall(t *testing.T) {
	native := &fakeNative{
		setProxyFunc: func(ckalkan.ProxyRequest) error {
			t.Fatal("SetProxy called native for invalid proxy")
			return nil
		},
	}
	client := &Client{library: native}

	err := client.SetProxy(context.Background(), Proxy{Enabled: true, Port: "3128"})
	if err == nil || !strings.Contains(err.Error(), "proxy address is empty") {
		t.Fatalf("SetProxy error = %v, want proxy address validation", err)
	}
}

func testCertificateDER(t *testing.T, commonName string) []byte {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(123456789),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}

	return der
}

func requireKalkanErrorCode(t *testing.T, err error, want ckalkan.ErrorCode) {
	t.Helper()

	got, ok := ckalkan.ErrorCodeOf(err)
	if err == nil || !ok || got != want {
		t.Fatalf("error = %v, want Kalkan code %v", err, want)
	}
}

func validCertificateInfoProps() map[ckalkan.CertProp]string {
	return map[ckalkan.CertProp]string{
		ckalkan.CertPropSubjectDN:    "CN = Native Subject\x00ignored",
		ckalkan.CertPropCertSN:       "certificateSerialNumber=010203",
		ckalkan.CertPropNotBefore:    "notBefore=02.01.2024 15:04:05 GMT",
		ckalkan.CertPropNotAfter:     "notAfter=03.01.2025 16:05:06 GMT",
		ckalkan.CertPropIssuerDN:     "CN = Native Issuer",
		ckalkan.CertPropPoliciesID:   "certificatePolicies=1.2.398.3.3.4, 1.2.398.3.3.5",
		ckalkan.CertPropKeyUsage:     "keyUsage=digitalSignature, nonRepudiation",
		ckalkan.CertPropExtKeyUsage:  "extendedKeyUsage=clientAuth, emailProtection",
		ckalkan.CertPropAuthKeyID:    "authorityKeyIdentifier=auth-key-id",
		ckalkan.CertPropSubjKeyID:    "subjectKeyIdentifier=subj-key-id",
		ckalkan.CertPropSignatureAlg: "GOST R 34.10-2015",
		ckalkan.CertPropPubKey:       "PUBLIC-KEY",
		ckalkan.CertPropOCSP:         "OCSP=http://ocsp.example.test",
		ckalkan.CertPropGetCRL:       "crlDistributionPoints=http://crl.example.test/root.crl",
		ckalkan.CertPropGetDeltaCRL:  "freshestCRL=http://crl.example.test/delta.crl",
	}
}
