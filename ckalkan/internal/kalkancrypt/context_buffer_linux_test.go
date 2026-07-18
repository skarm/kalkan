//go:build linux && cgo

package kalkancrypt_test

import (
	"strings"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestContextRejectsInvalidOutputCapacities(t *testing.T) {
	ctx := openContext(t)

	tests := []struct {
		name string
		run  func() error
	}{
		{name: "LastErrorString", run: func() error {
			_, err := ctx.LastErrorString(0)
			return err
		}},
		{name: "GetTokens", run: func() error {
			_, err := ctx.GetTokens(kcstPKCS12, 0)
			return err
		}},
		{name: "GetCertificatesList", run: func() error {
			_, err := ctx.GetCertificatesList(0)
			return err
		}},
		{name: "X509ExportCertificateFromStore", run: func() error {
			_, err := ctx.X509ExportCertificateFromStore("", certPEM, 0)
			return err
		}},
		{name: "X509CertificateGetInfo", run: func() error {
			_, err := ctx.X509CertificateGetInfo([]byte("cert"), certPropSubjectCommonName, 0)
			return err
		}},
		{name: "X509ValidateCertificate info buffer", run: func() error {
			_, err := ctx.X509ValidateCertificate(kalkancrypt.ValidateCertificateCall{Certificate: []byte("cert"), InfoCapacity: 0, OCSPCapacity: 1})
			return err
		}},
		{name: "X509ValidateCertificate OCSP buffer", run: func() error {
			_, err := ctx.X509ValidateCertificate(kalkancrypt.ValidateCertificateCall{Certificate: []byte("cert"), InfoCapacity: 1, OCSPCapacity: 0})
			return err
		}},
		{name: "HashData", run: func() error {
			_, err := ctx.HashData(kalkancrypt.HashDataCall{Algorithm: "sha256", Data: []byte("abc")})
			return err
		}},
		{name: "SignHash", run: func() error {
			_, err := ctx.SignHash(kalkancrypt.SignHashCall{Hash: []byte("hash")})
			return err
		}},
		{name: "SignData", run: func() error {
			_, err := ctx.SignData(kalkancrypt.SignDataCall{Data: []byte("data")})
			return err
		}},
		{name: "SignXML", run: func() error {
			_, err := ctx.SignXML(kalkancrypt.SignXMLCall{XML: []byte("<root/>"), Capacity: 0})
			return err
		}},
		{name: "SignWSSE", run: func() error {
			_, err := ctx.SignWSSE(kalkancrypt.SignWSSECall{XML: []byte("<root/>"), Capacity: 0})
			return err
		}},
		{name: "VerifyData data buffer", run: func() error {
			_, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{DataCapacity: 0, InfoCapacity: 1, CertCapacity: 1})
			return err
		}},
		{name: "VerifyData info buffer", run: func() error {
			_, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{DataCapacity: 1, InfoCapacity: 0, CertCapacity: 1})
			return err
		}},
		{name: "VerifyData cert buffer", run: func() error {
			_, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{DataCapacity: 1, InfoCapacity: 1, CertCapacity: 0})
			return err
		}},
		{name: "UVerifyData data buffer", run: func() error {
			_, err := ctx.UVerifyData(kalkancrypt.VerifyDataCall{DataCapacity: 0, InfoCapacity: 1, CertCapacity: 1})
			return err
		}},
		{name: "VerifyXML", run: func() error {
			_, err := ctx.VerifyXML(kalkancrypt.VerifyXMLCall{XML: []byte("<root/>")})
			return err
		}},
		{name: "GetCertFromXML", run: func() error {
			_, err := ctx.GetCertFromXML([]byte("<root/>"), 0, 0)
			return err
		}},
		{name: "GetSigAlgFromXML", run: func() error {
			_, err := ctx.GetSigAlgFromXML([]byte("<root/>"), 0)
			return err
		}},
		{name: "GetCertFromCMS", run: func() error {
			_, err := ctx.GetCertFromCMS(kalkancrypt.GetCertFromCMSCall{CMS: []byte("cms"), Flags: inBase64})
			return err
		}},
		{name: "ZipConVerify", run: func() error {
			_, err := ctx.ZipConVerify("/tmp/no-such.zip", inFile, 0)
			return err
		}},
		{name: "ZipConVerify negative capacity", run: func() error {
			_, err := ctx.ZipConVerify("/tmp/no-such.zip", inFile, -1)
			return err
		}},
		{name: "GetCertFromZipFile", run: func() error {
			_, err := ctx.GetCertFromZipFile(kalkancrypt.GetCertFromZipFileCall{ZipFile: "/tmp/no-such.zip", Flags: inFile})
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("expected invalid capacity error")
			}
			if !strings.Contains(err.Error(), "invalid buffer size") {
				t.Fatalf("error = %v, want invalid buffer size", err)
			}
		})
	}
}
