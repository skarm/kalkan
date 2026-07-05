package kalkancrypt_test

import (
	"errors"
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

const kcrLibraryNotInitialized uint64 = 0x08f00101

func TestClosedContextReturnsClosedErrors(t *testing.T) {
	t.Run("zero value", func(t *testing.T) {
		var ctx kalkancrypt.Context
		assertClosedContext(t, &ctx)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var ctx *kalkancrypt.Context
		assertClosedContext(t, ctx)
	})
}

func assertClosedContext(t *testing.T, ctx *kalkancrypt.Context) {
	t.Helper()

	if err := ctx.Close(); err != nil {
		t.Fatalf("Close on closed context returned error: %v", err)
	}

	ctx.ClearError()
	ctx.InitDebug()
	ctx.Finalize()
	ctx.XMLFinalize()
	ctx.SetTSAURL("https://tsa.example")

	statusCases := []struct {
		name string
		run  func() uint64
	}{
		{name: "Init", run: func() uint64 { return ctx.Init() }},
		{name: "LastError", run: func() uint64 { return ctx.LastError() }},
		{name: "LoadKeyStore", run: func() uint64 {
			return ctx.LoadKeyStore(1, "pass", "container", "alias")
		}},
		{name: "X509LoadCertificateFromFile", run: func() uint64 {
			return ctx.X509LoadCertificateFromFile("cert.pem", 2)
		}},
		{name: "X509LoadCertificateFromBuffer", run: func() uint64 {
			return ctx.X509LoadCertificateFromBuffer([]byte("cert"), 3)
		}},
		{name: "SetProxy", run: func() uint64 {
			return ctx.SetProxy(kalkancrypt.ProxyCall{Flags: 4, Address: "proxy"})
		}},
		{name: "ZipConSign", run: func() uint64 {
			return ctx.ZipConSign(kalkancrypt.ZipConSignCall{Alias: "alias", FilePath: "in.zip"})
		}},
	}
	for _, tc := range statusCases {
		if code := tc.run(); code != kcrLibraryNotInitialized {
			t.Fatalf("%s on closed context = %#x, want %#x", tc.name, code, kcrLibraryNotInitialized)
		}
	}

	errorCases := []struct {
		name string
		run  func() error
	}{
		{name: "LastErrorString", run: func() error {
			_, err := ctx.LastErrorString(16)
			return err
		}},
		{name: "GetTokens", run: func() error {
			_, err := ctx.GetTokens(5, 16)
			return err
		}},
		{name: "GetCertificatesList", run: func() error {
			_, err := ctx.GetCertificatesList(16)
			return err
		}},
		{name: "X509ExportCertificateFromStore", run: func() error {
			_, err := ctx.X509ExportCertificateFromStore("alias", 1, 16)
			return err
		}},
		{name: "X509CertificateGetInfo", run: func() error {
			_, err := ctx.X509CertificateGetInfo([]byte("cert"), 2, 16)
			return err
		}},
		{name: "X509ValidateCertificate", run: func() error {
			_, err := ctx.X509ValidateCertificate(kalkancrypt.ValidateCertificateCall{Certificate: []byte("cert")})
			return err
		}},
		{name: "HashData", run: func() error {
			_, err := ctx.HashData("sha256", 7, []byte("data"), 16)
			return err
		}},
		{name: "SignHash", run: func() error {
			_, err := ctx.SignHash("alias", 8, []byte("hash"), 16)
			return err
		}},
		{name: "SignData", run: func() error {
			_, err := ctx.SignData("alias", 9, []byte("data"), []byte("sig"), 16)
			return err
		}},
		{name: "SignXML", run: func() error {
			_, err := ctx.SignXML(kalkancrypt.SignXMLCall{Alias: "alias", XML: []byte("<a/>")})
			return err
		}},
		{name: "SignWSSE", run: func() error {
			_, err := ctx.SignWSSE(kalkancrypt.SignWSSECall{Alias: "alias", XML: []byte("<a/>")})
			return err
		}},
		{name: "VerifyData", run: func() error {
			_, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{Alias: "alias", Data: []byte("data")})
			return err
		}},
		{name: "UVerifyData", run: func() error {
			_, err := ctx.UVerifyData(kalkancrypt.VerifyDataCall{Alias: "alias", Data: []byte("data")})
			return err
		}},
		{name: "VerifyXML", run: func() error {
			_, err := ctx.VerifyXML("alias", 10, []byte("<a/>"), 16)
			return err
		}},
		{name: "GetCertFromXML", run: func() error {
			_, err := ctx.GetCertFromXML([]byte("<a/>"), 11, 16)
			return err
		}},
		{name: "GetSigAlgFromXML", run: func() error {
			_, err := ctx.GetSigAlgFromXML([]byte("<a/>"), 16)
			return err
		}},
		{name: "GetCertFromCMS", run: func() error {
			_, err := ctx.GetCertFromCMS([]byte("cms"), 12, 13, 16)
			return err
		}},
		{name: "ZipConVerify", run: func() error {
			_, err := ctx.ZipConVerify("archive.zip", 14, 16)
			return err
		}},
		{name: "GetCertFromZipFile", run: func() error {
			_, err := ctx.GetCertFromZipFile("archive.zip", 15, 16, 17)
			return err
		}},
	}
	for _, tc := range errorCases {
		if err := tc.run(); !errors.Is(err, kalkancrypt.ErrClosed) {
			t.Fatalf("%s on closed context returned %v, want ErrClosed", tc.name, err)
		}
	}

	if code, ts := ctx.GetTimeFromSig([]byte("cms"), 18, 19); code != kcrLibraryNotInitialized || ts != 0 {
		t.Fatalf("GetTimeFromSig on closed context = (%#x, %d), want (%#x, 0)", code, ts, kcrLibraryNotInitialized)
	}
}
