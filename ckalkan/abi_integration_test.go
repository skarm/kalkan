package ckalkan_test

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestNativeFileInputsRejectEmbeddedNUL(t *testing.T) {
	client := newIntegrationClient(t)
	path := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := []byte(path + "\x00different")
	for _, flags := range []ckalkan.Flag{ckalkan.InFile, ckalkan.InFile | ckalkan.InBase64} {
		tests := []struct {
			name string
			call func() error
		}{
			{name: "HashData", call: func() error {
				_, err := client.HashData(ckalkan.SHA256, flags, input)
				return err
			}},
			{name: "SignData", call: func() error {
				_, err := client.SignData(ckalkan.SignDataRequest{Flags: flags | ckalkan.SignCMS, Data: input})
				return err
			}},
			{name: "VerifyData", call: func() error {
				_, err := client.VerifyData(ckalkan.VerifyDataRequest{Flags: flags | ckalkan.SignCMS, Signature: input})
				return err
			}},
			{name: "X509ValidateCertificate", call: func() error {
				_, err := client.X509ValidateCertificate(ckalkan.ValidateCertificateRequest{
					Flags: flags, Certificate: input, ValidationType: ckalkan.UseNothing,
				})
				return err
			}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				if err := test.call(); err == nil || !strings.Contains(err.Error(), "NUL") {
					t.Fatalf("flags %x: error = %v, want NUL path rejection", flags, err)
				}
			})
		}
		_, err := client.GetTimeFromSig(input, flags, 0)
		if code, ok := ckalkan.ErrorCodeOf(err); !ok || code != ckalkan.ErrorParam {
			t.Fatalf("GetTimeFromSig flags %x: error = %v, want native parameter error", flags, err)
		}
	}
}

// TestNativeABISmoke checks that calls cross the ABI and return Go-visible
// status. Operation-specific integration tests assert successful results and
// expected cryptographic failures.
func TestNativeABISmoke(t *testing.T) {
	cli := newIntegrationClient(t)
	var err error

	check := func(name string, err error) {
		t.Helper()
		if err == nil {
			return
		}
		if _, ok := errors.AsType[*ckalkan.KalkanError](err); !ok {
			t.Fatalf("%s returned non-Kalkan error: %T %v", name, err, err)
		}
	}

	check("Init", cli.Init())
	check("InitDebug", cli.InitDebug())
	check("SetTSAURL", cli.SetTSAURL("http://localhost/tsa"))
	check("SetProxy", cli.SetProxy(ckalkan.ProxyRequest{Flags: ckalkan.ProxyOff}))
	_, _ = cli.GetLastErrorString()
	_ = cli.GetLastError()

	_, err = cli.GetTokens(ckalkan.StorePKCS12)
	check("GetTokens", err)
	_, err = cli.GetCertificatesList()
	check("GetCertificatesList", err)
	check("LoadKeyStore", cli.LoadKeyStore(ckalkan.StorePKCS12, "bad-password", "/tmp/ckalkan-no-such-key.p12", ""))

	check("X509LoadCertificateFromFile", cli.X509LoadCertificateFromFile("/tmp/ckalkan-no-such-cert.cer", ckalkan.CertCA))
	check("X509LoadCertificateFromBuffer", cli.X509LoadCertificateFromBuffer([]byte("not-a-cert"), ckalkan.CertPEM))
	_, err = cli.X509ExportCertificateFromStore("missing-alias", ckalkan.CertPEM)
	check("X509ExportCertificateFromStore", err)
	_, err = cli.X509CertificateGetInfo([]byte("not-a-cert"), ckalkan.CertPropSubjectDN)
	check("X509CertificateGetInfo", err)
	_, err = cli.X509ValidateCertificate(ckalkan.ValidateCertificateRequest{Certificate: []byte("not-a-cert"), ValidationType: ckalkan.UseOCSP})
	check("X509ValidateCertificate", err)

	_, err = cli.HashData(ckalkan.SHA256, 0, []byte("abc"))
	check("HashData", err)
	_, err = cli.SignHash("missing-alias", ckalkan.OutBase64, []byte("hash"))
	check("SignHash", err)
	_, err = cli.SignData(ckalkan.SignDataRequest{Alias: "missing-alias", Flags: ckalkan.SignCMS | ckalkan.OutBase64, Data: []byte("data")})
	check("SignData", err)
	_, err = cli.SignXML(ckalkan.SignXMLRequest{Alias: "missing-alias", XML: []byte("<root/>"), Flags: ckalkan.XMLInclC14N})
	check("SignXML", err)
	_, err = cli.SignWSSE(ckalkan.SignWSSERequest{Alias: "missing-alias", XML: []byte("<root/>"), Flags: ckalkan.XMLInclC14N})
	check("SignWSSE", err)

	_, err = cli.VerifyData(ckalkan.VerifyDataRequest{Data: []byte("data"), Signature: []byte("sig"), Flags: ckalkan.SignCMS})
	check("VerifyData", err)
	_, err = cli.VerifyXML("", ckalkan.XMLInclC14N, []byte("<root/>"))
	check("VerifyXML", err)
	_, err = cli.GetCertFromXML([]byte("<root/>"), 0)
	check("GetCertFromXML", err)
	_, err = cli.GetSigAlgFromXML([]byte("<root/>"))
	check("GetSigAlgFromXML", err)
	_, err = cli.GetCertFromCMS([]byte("cms"), 0, ckalkan.InBase64)
	check("GetCertFromCMS", err)
	_, err = cli.GetTimeFromSig([]byte("cms"), ckalkan.InBase64, 0)
	check("GetTimeFromSig", err)

	_, err = cli.ZipConVerify("/tmp/ckalkan-no-such.zip", ckalkan.InFile)
	check("ZipConVerify", err)
	check("ZipConSign", cli.ZipConSign(ckalkan.ZipConSignRequest{Alias: "missing-alias", FilePath: "/tmp/ckalkan-no-such.txt", Name: "out.zip", OutDir: "/tmp", Flags: ckalkan.InFile}))
	_, err = cli.GetCertFromZipFile("/tmp/ckalkan-no-such.zip", ckalkan.InFile, 0)
	check("GetCertFromZipFile", err)
}

func TestNativeClientBasics(t *testing.T) {
	cli := newIntegrationClient(t, ckalkan.WithMaxBufferSize(1024))

	hash, err := cli.HashData(ckalkan.SHA256, 0, []byte("abc"))
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}
	want := sha256.Sum256([]byte("abc"))
	if string(hash) != string(want[:]) {
		t.Fatalf("HashData returned %x, want %x", hash, want)
	}

	if err := cli.LoadKeyStore(ckalkan.StorePKCS12, "bad-password", "/tmp/ckalkan-no-such-key.p12", ""); err == nil {
		t.Fatal("LoadKeyStore with a missing file unexpectedly succeeded")
	} else if _, ok := ckalkan.ErrorCodeOf(err); !ok {
		t.Fatalf("LoadKeyStore returned a non-Kalkan error: %T %v", err, err)
	}
}
