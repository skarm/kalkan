//go:build linux && cgo

package ckalkan_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestNewFailureReleasesClientSlot(t *testing.T) {
	if _, err := ckalkan.New(ckalkan.WithLibrary(filepath.Join(t.TempDir(), "missing.so"))); err == nil {
		t.Fatal("expected New to fail for a missing library")
	}

	cli, err := ckalkan.New(ckalkan.WithLibrary(buildStubLibrary(t)))
	if err != nil {
		t.Fatalf("New after failed New returned %v, want success", err)
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestNewDoesNotReadTextSymlinkLibraryFallback(t *testing.T) {
	so := buildStubLibrary(t)
	linkFile := filepath.Join(filepath.Dir(so), "libkalkancryptwr-64.so")
	if err := os.WriteFile(linkFile, []byte(filepath.Base(so)), 0o600); err != nil {
		t.Fatal(err)
	}

	cli, err := ckalkan.New(ckalkan.WithLibrary(linkFile))
	if err == nil {
		_ = cli.Close()
		t.Fatal("New succeeded by reading a text symlink fallback; want exact library path load failure")
	}
}

func TestMethodsAgainstStubLibrary(t *testing.T) {
	so := buildStubLibrary(t)

	cli, err := ckalkan.New(ckalkan.WithLibrary(so), ckalkan.WithBufferSize(2), ckalkan.WithListBufferSize(64))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer func() {
		if err := cli.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	}()

	if err := cli.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if err := cli.InitDebug(); err != nil {
		t.Fatalf("InitDebug failed: %v", err)
	}
	if err := cli.SetTSAURL("http://tsa.example"); err != nil {
		t.Fatalf("SetTSAURL failed: %v", err)
	}
	if err := cli.SetProxy(ckalkan.ProxyRequest{Flags: ckalkan.ProxyOn | ckalkan.ProxyAuth, Address: "127.0.0.1", Port: "3128", User: "u", Password: "p"}); err != nil {
		t.Fatalf("SetProxy failed: %v", err)
	}

	tokens, err := cli.GetTokens(ckalkan.StorePKCS12)
	if err != nil {
		t.Fatalf("GetTokens failed: %v", err)
	}
	if tokens.Count != 2 || tokens.Data != "token-a;token-b" {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}

	certs, err := cli.GetCertificatesList()
	if err != nil {
		t.Fatalf("GetCertificatesList failed: %v", err)
	}
	if certs.Count != 1 || certs.Data != "cert-a" {
		t.Fatalf("unexpected certificates: %+v", certs)
	}

	if err := cli.LoadKeyStore(ckalkan.StorePKCS12, "pass", "/tmp/key.p12", "alias"); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}
	if err := cli.X509LoadCertificateFromFile("/tmp/ca.cer", ckalkan.CertCA); err != nil {
		t.Fatalf("X509LoadCertificateFromFile failed: %v", err)
	}
	if err := cli.X509LoadCertificateFromBuffer([]byte("cert"), ckalkan.CertPEM); err != nil {
		t.Fatalf("X509LoadCertificateFromBuffer failed: %v", err)
	}

	assertBytesCall(t, "X509ExportCertificateFromStore", []byte("CERT"), func() ([]byte, error) {
		return cli.X509ExportCertificateFromStore("alias", ckalkan.CertPEM)
	})
	assertBytesCall(t, "X509CertificateGetInfo", []byte("INFO"), func() ([]byte, error) {
		return cli.X509CertificateGetInfo([]byte("cert"), ckalkan.CertPropSubjectDN)
	})
	assertBytesCall(t, "HashData", []byte("HASH"), func() ([]byte, error) {
		return cli.HashData(ckalkan.SHA256, ckalkan.InBase64|ckalkan.OutBase64, []byte("data"))
	})
	assertBytesCall(t, "SignHash", []byte("SIGNHASH"), func() ([]byte, error) {
		return cli.SignHash("alias", ckalkan.OutBase64, []byte("hash"))
	})
	assertBytesCall(t, "SignData", []byte("SIGNDATA"), func() ([]byte, error) {
		return cli.SignData("alias", ckalkan.SignCMS|ckalkan.OutBase64, []byte("data"), nil)
	})
	assertBytesCall(t, "SignXML", []byte("<signed/>"), func() ([]byte, error) {
		return cli.SignXML(ckalkan.SignXMLRequest{Alias: "alias", XML: []byte("<root/>"), Flags: ckalkan.XMLInclC14N})
	})
	assertBytesCall(t, "GetCertFromXML", []byte("XMLCERT"), func() ([]byte, error) {
		return cli.GetCertFromXML([]byte("<root/>"), 0)
	})
	assertBytesCall(t, "GetCertFromCMS", []byte("CMSCERT"), func() ([]byte, error) {
		return cli.GetCertFromCMS([]byte("cms"), 0, ckalkan.InBase64)
	})
	assertBytesCall(t, "SignWSSE", []byte("<wsse/>"), func() ([]byte, error) {
		return cli.SignWSSE(ckalkan.SignWSSERequest{Alias: "alias", XML: []byte("<root/>"), Flags: ckalkan.XMLInclC14N})
	})
	assertBytesCall(t, "GetCertFromZipFile", []byte("ZIPCERT"), func() ([]byte, error) {
		return cli.GetCertFromZipFile("/tmp/a.zip", ckalkan.InFile, 0)
	})

	validate, err := cli.X509ValidateCertificate(ckalkan.ValidateCertificateRequest{Certificate: []byte("cert"), ValidationType: ckalkan.UseOCSP, ValidationPath: "http://ocsp"})
	if err != nil {
		t.Fatalf("X509ValidateCertificate failed: %v", err)
	}
	if validate.Info != "VALID" || string(validate.OCSPResponse) != "OCSP" {
		t.Fatalf("unexpected validation result: %+v", validate)
	}

	verify, err := cli.VerifyData(ckalkan.VerifyDataRequest{Alias: "alias", Data: []byte("data"), Signature: []byte("sig"), Flags: ckalkan.SignCMS})
	if err != nil {
		t.Fatalf("VerifyData failed: %v", err)
	}
	if string(verify.Data) != "DATA" || verify.VerifyInfo != "VERIFY" || string(verify.Cert) != "CERT" {
		t.Fatalf("unexpected VerifyData result: %+v", verify)
	}

	uverify, err := cli.UVerifyData(ckalkan.VerifyDataRequest{Alias: "alias", Data: []byte("data"), Signature: []byte("sig"), Flags: ckalkan.SignCMS})
	if err != nil {
		t.Fatalf("UVerifyData failed: %v", err)
	}
	if string(uverify.Data) != "UDATA" || uverify.VerifyInfo != "UVERIFY" || string(uverify.Cert) != "UCERT" {
		t.Fatalf("unexpected UVerifyData result: %+v", uverify)
	}

	xmlVerify, err := cli.VerifyXML("alias", ckalkan.XMLInclC14N, []byte("<root/>"))
	if err != nil {
		t.Fatalf("VerifyXML failed: %v", err)
	}
	if xmlVerify != "XMLVERIFY" {
		t.Fatalf("unexpected VerifyXML result: %q", xmlVerify)
	}

	sigAlg, err := cli.GetSigAlgFromXML([]byte("<root/>"))
	if err != nil {
		t.Fatalf("GetSigAlgFromXML failed: %v", err)
	}
	if sigAlg != "ALG" {
		t.Fatalf("unexpected signature algorithm: %q", sigAlg)
	}

	ts, err := cli.GetTimeFromSig([]byte("cms"), ckalkan.InBase64, 0)
	if err != nil {
		t.Fatalf("GetTimeFromSig failed: %v", err)
	}
	if !ts.Equal(time.Unix(12345, 0)) {
		t.Fatalf("unexpected signature time: %v", ts)
	}

	zipInfo, err := cli.ZipConVerify("/tmp/a.zip", ckalkan.InFile)
	if err != nil {
		t.Fatalf("ZipConVerify failed: %v", err)
	}
	if zipInfo != "ZIPVERIFY" {
		t.Fatalf("unexpected ZipConVerify result: %q", zipInfo)
	}
	if err := cli.ZipConSign(ckalkan.ZipConSignRequest{Alias: "alias", FilePath: "/tmp/a.zip", Name: "a.zip", OutDir: "/tmp", Flags: ckalkan.InFile}); err != nil {
		t.Fatalf("ZipConSign failed: %v", err)
	}

	lastCode := cli.GetLastError()
	if lastCode != ckalkan.ErrorOK {
		t.Fatalf("unexpected last error: %s", lastCode.Hex())
	}
	lastCode, lastMessage := cli.GetLastErrorString()
	if lastCode != ckalkan.ErrorOK || lastMessage != "OK" {
		t.Fatalf("unexpected last error string: code=%s message=%q", lastCode.Hex(), lastMessage)
	}
}

func TestOnlyOneActiveClientPerProcess(t *testing.T) {
	so := buildStubLibrary(t)

	first, err := ckalkan.New(ckalkan.WithLibrary(so))
	if err != nil {
		t.Fatalf("first New failed: %v", err)
	}
	if second, err := ckalkan.New(ckalkan.WithLibrary(so)); !errors.Is(err, ckalkan.ErrAlreadyOpen) {
		if second != nil {
			_ = second.Close()
		}
		_ = first.Close()
		t.Fatalf("second New error = %v, want ErrAlreadyOpen", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}

	third, err := ckalkan.New(ckalkan.WithLibrary(so))
	if err != nil {
		t.Fatalf("New after Close failed: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatalf("third Close failed: %v", err)
	}
}

func assertBytesCall(t *testing.T, name string, want []byte, call func() ([]byte, error)) {
	t.Helper()
	got, err := call()
	if err != nil {
		t.Fatalf("%s failed: %v", name, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s returned %q, want %q", name, got, want)
	}
}

func buildStubLibrary(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc is required to build the stub shared library")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "stub.c")
	outName := "libmockkalkan.so"
	args := make([]string, 0, 6)
	args = append(args, "-shared", "-fPIC", "-I"+filepath.Join(wd, "internal", "kalkancrypt"))
	sharedLibrary := filepath.Join(dir, outName)
	if err := os.WriteFile(src, []byte(stubSource), 0o600); err != nil {
		t.Fatal(err)
	}
	args = append(args, "-o", sharedLibrary, src)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cc, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cannot build stub library: %v\n%s", err, out)
	}
	return sharedLibrary
}
