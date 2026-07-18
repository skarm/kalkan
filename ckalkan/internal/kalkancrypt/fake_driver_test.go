package kalkancrypt

import (
	"strconv"
	"strings"
)

type fakeDriver struct {
	closeCalls             int
	hashCalls              int
	signHashCall           SignHashCall
	signDataCall           SignDataCall
	verifyXMLCall          VerifyXMLCall
	getCertFromCMSCall     GetCertFromCMSCall
	getCertFromZipFileCall GetCertFromZipFileCall
}

func (f *fakeDriver) Close() error { f.closeCalls++; return nil }
func (f *fakeDriver) ClearError()  {}
func (f *fakeDriver) Init() uint64 { return 0 }
func (f *fakeDriver) InitDebug()   {}
func (f *fakeDriver) Finalize()    {}
func (f *fakeDriver) XMLFinalize() {}
func (f *fakeDriver) LastError() uint64 {
	return 0
}
func (f *fakeDriver) LastErrorString(capacity int) (BufferResult, error) {
	return BufferResult{Data: []byte("ok"), OutLen: len("ok")}, nil
}
func (f *fakeDriver) GetTokens(uint64, int) (ListResult, error) { return ListResult{}, nil }
func (f *fakeDriver) GetCertificatesList(int) (ListResult, error) {
	return ListResult{}, nil
}
func (f *fakeDriver) LoadKeyStore(int, string, string, string) uint64  { return 0 }
func (f *fakeDriver) X509LoadCertificateFromFile(string, int) uint64   { return 0 }
func (f *fakeDriver) X509LoadCertificateFromBuffer([]byte, int) uint64 { return 0 }
func (f *fakeDriver) X509ExportCertificateFromStore(string, int, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) X509CertificateGetInfo([]byte, int, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) X509ValidateCertificate(ValidateCertificateCall) (ValidateResult, error) {
	return ValidateResult{}, nil
}
func (f *fakeDriver) HashData(call HashDataCall) (BufferResult, error) {
	f.hashCalls++

	flagsText := strconv.Itoa(call.Flags)
	capacityText := strconv.Itoa(call.Capacity)

	var out strings.Builder
	out.Grow(len("hash::::") + len(call.Algorithm) + len(flagsText) + len(call.Data) + len(capacityText))
	out.WriteString("hash:")
	out.WriteString(call.Algorithm)
	out.WriteByte(':')
	out.WriteString(flagsText)
	out.WriteByte(':')
	out.Write(call.Data)
	out.WriteByte(':')
	out.WriteString(capacityText)

	data := []byte(out.String())

	return BufferResult{Data: data, OutLen: len(data)}, nil
}
func (f *fakeDriver) SignHash(call SignHashCall) (BufferResult, error) {
	f.signHashCall = call

	return BufferResult{}, nil
}
func (f *fakeDriver) SignData(call SignDataCall) (BufferResult, error) {
	f.signDataCall = call

	return BufferResult{}, nil
}
func (f *fakeDriver) SignXML(SignXMLCall) (BufferResult, error)        { return BufferResult{}, nil }
func (f *fakeDriver) SignWSSE(SignWSSECall) (BufferResult, error)      { return BufferResult{}, nil }
func (f *fakeDriver) VerifyData(VerifyDataCall) (VerifyResult, error)  { return VerifyResult{}, nil }
func (f *fakeDriver) UVerifyData(VerifyDataCall) (VerifyResult, error) { return VerifyResult{}, nil }
func (f *fakeDriver) VerifyXML(call VerifyXMLCall) (BufferResult, error) {
	f.verifyXMLCall = call

	return BufferResult{}, nil
}
func (f *fakeDriver) GetCertFromXML([]byte, int, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) GetSigAlgFromXML([]byte, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) GetTimeFromSig([]byte, int, int) (uint64, int64) { return 0, 0 }
func (f *fakeDriver) GetCertFromCMS(call GetCertFromCMSCall) (BufferResult, error) {
	f.getCertFromCMSCall = call

	return BufferResult{}, nil
}
func (f *fakeDriver) SetTSAURL(string) uint64   { return 0 }
func (f *fakeDriver) SetProxy(ProxyCall) uint64 { return 0 }
func (f *fakeDriver) ZipConVerify(string, int, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) ZipConSign(ZipConSignCall) uint64 { return 0 }
func (f *fakeDriver) GetCertFromZipFile(call GetCertFromZipFileCall) (BufferResult, error) {
	f.getCertFromZipFileCall = call

	return BufferResult{}, nil
}
