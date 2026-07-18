package ckalkan_test

import (
	"crypto/sha256"
	"errors"
	"testing"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestNativeABI(t *testing.T) {
	cli := newRealClient(t)
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
	cli := newRealClient(t, ckalkan.WithMaxBufferSize(1024))

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
