//go:build linux && cgo

package kalkancrypt_test

import (
	"testing"

	kalkancrypt "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestContextMethodsReturnNativeStatusForInvalidInputs(t *testing.T) {
	ctx := openContext(t)

	ctx.InitDebug()
	ctx.SetTSAURL("http://localhost/tsa")
	ctx.ClearError()
	if code := ctx.SetProxy(kalkancrypt.ProxyCall{Flags: proxyOff}); code != kcrOK {
		t.Fatalf("SetProxy(ProxyOff) = %#x, want %#x", code, kcrOK)
	}
	_ = ctx.LastError()
	if _, err := ctx.LastErrorString(4096); err != nil {
		t.Fatalf("LastErrorString returned Go error: %v", err)
	}

	if _, err := ctx.GetTokens(kcstPKCS12, 4096); err != nil {
		t.Fatalf("GetTokens returned Go error: %v", err)
	}
	if _, err := ctx.GetCertificatesList(4096); err != nil {
		t.Fatalf("GetCertificatesList returned Go error: %v", err)
	}

	requireNativeFailureCode(t, "LoadKeyStore(missing)", ctx.LoadKeyStore(kcstPKCS12, "bad-password", "/tmp/ckalkan-no-such-key.p12", ""))
	requireNativeFailureCode(t, "X509LoadCertificateFromFile(missing)", ctx.X509LoadCertificateFromFile("/tmp/ckalkan-no-such-cert.cer", certCA))
	requireNativeFailureCode(t, "X509LoadCertificateFromBuffer(invalid)", ctx.X509LoadCertificateFromBuffer([]byte("not-a-cert"), certPEM))

	exported, err := ctx.X509ExportCertificateFromStore("missing-alias", certPEM, 4096)
	requireBufferNativeFailure(t, "X509ExportCertificateFromStore(missing)", exported, err)
	certInfo, err := ctx.X509CertificateGetInfo([]byte("not-a-cert"), certPropSubjectCommonName, 4096)
	requireBufferNativeFailure(t, "X509CertificateGetInfo(invalid)", certInfo, err)
	validation, err := ctx.X509ValidateCertificate(kalkancrypt.ValidateCertificateCall{
		Certificate:    []byte("not-a-cert"),
		ValidationType: useOCSP,
		InfoCapacity:   4096,
		OCSPCapacity:   4096,
	})
	if err != nil {
		t.Fatalf("X509ValidateCertificate returned Go error: %v", err)
	}
	requireNativeFailureCode(t, "X509ValidateCertificate(invalid)", validation.Code)

	signedHash, err := ctx.SignHash("missing-alias", signCMS|outBase64, []byte("hash"), 4096)
	requireBufferNativeFailure(t, "SignHash(missing)", signedHash, err)
	signedData, err := ctx.SignData("missing-alias", signCMS|outBase64, []byte("data"), nil, 4096)
	requireBufferNativeFailure(t, "SignData(missing)", signedData, err)
	signedXML, err := ctx.SignXML(kalkancrypt.SignXMLCall{Alias: "missing-alias", Flags: signCMS, XML: []byte("<root/>"), Capacity: 4096})
	requireBufferNativeFailure(t, "SignXML(missing)", signedXML, err)
	signedWSSE, err := ctx.SignWSSE(kalkancrypt.SignWSSECall{Alias: "missing-alias", Flags: signCMS, XML: []byte("<root/>"), Capacity: 4096})
	requireBufferNativeFailure(t, "SignWSSE(missing)", signedWSSE, err)

	verified, err := ctx.VerifyData(kalkancrypt.VerifyDataCall{
		Flags:        signCMS,
		Data:         []byte("data"),
		Signature:    []byte("sig"),
		DataCapacity: 4096,
		InfoCapacity: 4096,
		CertCapacity: 4096,
	})
	requireVerifyNativeFailure(t, "VerifyData(invalid)", verified, err)
	unsignedVerified, err := ctx.UVerifyData(kalkancrypt.VerifyDataCall{
		Flags:        signCMS,
		Data:         []byte("data"),
		Signature:    []byte("sig"),
		DataCapacity: 4096,
		InfoCapacity: 4096,
		CertCapacity: 4096,
	})
	requireVerifyNativeFailure(t, "UVerifyData(invalid)", unsignedVerified, err)

	xmlVerified, err := ctx.VerifyXML("", signCMS, []byte("<root/>"), 4096)
	requireBufferNativeFailure(t, "VerifyXML(unsigned)", xmlVerified, err)
	certFromXML, err := ctx.GetCertFromXML([]byte("<root/>"), 0, 4096)
	requireBufferNativeFailure(t, "GetCertFromXML(unsigned)", certFromXML, err)
	sigAlgFromXML, err := ctx.GetSigAlgFromXML([]byte("<root/>"), 4096)
	requireBufferNativeFailure(t, "GetSigAlgFromXML(unsigned)", sigAlgFromXML, err)
	certFromCMS, err := ctx.GetCertFromCMS([]byte("cms"), 0, inBase64, 4096)
	requireBufferNativeFailure(t, "GetCertFromCMS(invalid)", certFromCMS, err)
	if code, _ := ctx.GetTimeFromSig([]byte("cms"), inBase64, 0); code == kcrOK {
		t.Fatal("GetTimeFromSig(invalid) unexpectedly returned KCR_OK")
	}

	zipVerified, err := ctx.ZipConVerify("/tmp/ckalkan-no-such.zip", inFile, 4096)
	requireBufferNativeFailure(t, "ZipConVerify(missing)", zipVerified, err)
	requireNativeFailureCode(t, "ZipConSign(missing)", ctx.ZipConSign(kalkancrypt.ZipConSignCall{
		Alias:    "missing-alias",
		FilePath: "/tmp/ckalkan-no-such.txt",
		Name:     "out.zip",
		OutDir:   "/tmp",
		Flags:    inFile,
	}))
	certFromZip, err := ctx.GetCertFromZipFile("/tmp/ckalkan-no-such.zip", inFile, 0, 4096)
	requireBufferNativeFailure(t, "GetCertFromZipFile(missing)", certFromZip, err)

	ctx.XMLFinalize()
	ctx.Finalize()
}
