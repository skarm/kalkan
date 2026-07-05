package kalkancrypt

import (
	"strconv"
	"strings"
)

type fakeDriver struct {
	closeCalls int
	hashCalls  int
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
	return BufferResult{Data: []byte("ok"), OutLen: capacity}, nil
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
func (f *fakeDriver) HashData(algorithm string, flags int, data []byte, capacity int) (BufferResult, error) {
	f.hashCalls++

	flagsText := strconv.Itoa(flags)
	capacityText := strconv.Itoa(capacity)

	var out strings.Builder
	out.Grow(len("hash::::") + len(algorithm) + len(flagsText) + len(data) + len(capacityText))
	out.WriteString("hash:")
	out.WriteString(algorithm)
	out.WriteByte(':')
	out.WriteString(flagsText)
	out.WriteByte(':')
	out.Write(data)
	out.WriteByte(':')
	out.WriteString(capacityText)

	return BufferResult{Data: []byte(out.String())}, nil
}
func (f *fakeDriver) SignHash(string, int, []byte, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) SignData(string, int, []byte, []byte, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) SignXML(SignXMLCall) (BufferResult, error)        { return BufferResult{}, nil }
func (f *fakeDriver) SignWSSE(SignWSSECall) (BufferResult, error)      { return BufferResult{}, nil }
func (f *fakeDriver) VerifyData(VerifyDataCall) (VerifyResult, error)  { return VerifyResult{}, nil }
func (f *fakeDriver) UVerifyData(VerifyDataCall) (VerifyResult, error) { return VerifyResult{}, nil }
func (f *fakeDriver) VerifyXML(string, int, []byte, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) GetCertFromXML([]byte, int, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) GetSigAlgFromXML([]byte, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) GetTimeFromSig([]byte, int, int) (uint64, int64) { return 0, 0 }
func (f *fakeDriver) GetCertFromCMS([]byte, int, int, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) SetTSAURL(string) uint64   { return 0 }
func (f *fakeDriver) SetProxy(ProxyCall) uint64 { return 0 }
func (f *fakeDriver) ZipConVerify(string, int, int) (BufferResult, error) {
	return BufferResult{}, nil
}
func (f *fakeDriver) ZipConSign(ZipConSignCall) uint64 { return 0 }
func (f *fakeDriver) GetCertFromZipFile(string, int, int, int) (BufferResult, error) {
	return BufferResult{}, nil
}
