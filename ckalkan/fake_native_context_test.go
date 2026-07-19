package ckalkan

import "github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"

type fakeNativeContext struct {
	closeFunc               func() error
	clearErrorFunc          func()
	finalizeFunc            func()
	getTokensFunc           func(uint64, int) (kalkancrypt.ListResult, error)
	getCertificatesListFunc kalkancrypt.ListBufferFunc
	hashDataFunc            func(kalkancrypt.HashDataCall) (kalkancrypt.BufferResult, error)
	lastErrorStringFunc     kalkancrypt.OutputBufferFunc
	signHashFunc            func(kalkancrypt.SignHashCall) (kalkancrypt.BufferResult, error)
	signDataFunc            func(kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error)
	signXMLFunc             func(kalkancrypt.SignXMLCall) (kalkancrypt.BufferResult, error)
	signWSSEFunc            func(kalkancrypt.SignWSSECall) (kalkancrypt.BufferResult, error)
	validateCertificateFunc func(kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error)
	verifyDataFunc          func(kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error)
	verifyXMLFunc           func(kalkancrypt.VerifyXMLCall) (kalkancrypt.BufferResult, error)
	x509ExportFunc          func(string, int, int) (kalkancrypt.BufferResult, error)
	x509LoadBufferFunc      func([]byte, int) uint64
	x509InfoFunc            func([]byte, int, int) (kalkancrypt.BufferResult, error)
	getCertFromXMLFunc      func([]byte, int, int) (kalkancrypt.BufferResult, error)
	getTimeFromSigFunc      func([]byte, int, int) (uint64, int64)
	getCertFromCMSFunc      func(kalkancrypt.GetCertFromCMSCall) (kalkancrypt.BufferResult, error)
	getCertFromZipFileFunc  func(kalkancrypt.GetCertFromZipFileCall) (kalkancrypt.BufferResult, error)
	getSigAlgFromXMLFunc    func([]byte, int) (kalkancrypt.BufferResult, error)
	setTSAURLFunc           func(string) uint64
	xmlFinalizeFunc         func()
	zipConVerifyFunc        func(string, int, int) (kalkancrypt.BufferResult, error)
	zipConSignFunc          func(kalkancrypt.ZipConSignCall) uint64
}

func (f *fakeNativeContext) Close() error {
	if f.closeFunc != nil {
		return f.closeFunc()
	}
	return nil
}
func (f *fakeNativeContext) ClearError() {
	if f.clearErrorFunc != nil {
		f.clearErrorFunc()
	}
}
func (f *fakeNativeContext) Init() uint64 { return uint64(ErrorOK) }
func (f *fakeNativeContext) InitDebug()   {}
func (f *fakeNativeContext) Finalize() {
	if f.finalizeFunc != nil {
		f.finalizeFunc()
	}
}
func (f *fakeNativeContext) XMLFinalize() {
	if f.xmlFinalizeFunc != nil {
		f.xmlFinalizeFunc()
	}
}
func (f *fakeNativeContext) LastError() uint64 {
	return uint64(ErrorOK)
}
func (f *fakeNativeContext) LastErrorString(capacity int) (kalkancrypt.BufferResult, error) {
	if f.lastErrorStringFunc != nil {
		return f.lastErrorStringFunc(capacity)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("OK"), OutLen: 2}, nil
}
func (f *fakeNativeContext) GetTokens(storage uint64, capacity int) (kalkancrypt.ListResult, error) {
	if f.getTokensFunc != nil {
		return f.getTokensFunc(storage, capacity)
	}
	return kalkancrypt.ListResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) GetCertificatesList(capacity int) (kalkancrypt.ListResult, error) {
	if f.getCertificatesListFunc != nil {
		return f.getCertificatesListFunc(capacity)
	}
	return kalkancrypt.ListResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) LoadKeyStore(int, string, string, string) uint64 {
	return uint64(ErrorOK)
}
func (f *fakeNativeContext) X509LoadCertificateFromFile(string, int) uint64 {
	return uint64(ErrorOK)
}
func (f *fakeNativeContext) X509LoadCertificateFromBuffer(cert []byte, format int) uint64 {
	if f.x509LoadBufferFunc != nil {
		return f.x509LoadBufferFunc(cert, format)
	}
	return uint64(ErrorOK)
}
func (f *fakeNativeContext) X509ExportCertificateFromStore(alias string, format, capacity int) (kalkancrypt.BufferResult, error) {
	if f.x509ExportFunc != nil {
		return f.x509ExportFunc(alias, format, capacity)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) X509CertificateGetInfo(cert []byte, prop, capacity int) (kalkancrypt.BufferResult, error) {
	if f.x509InfoFunc != nil {
		return f.x509InfoFunc(cert, prop, capacity)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) X509ValidateCertificate(call kalkancrypt.ValidateCertificateCall) (kalkancrypt.ValidateResult, error) {
	if f.validateCertificateFunc != nil {
		return f.validateCertificateFunc(call)
	}
	return kalkancrypt.ValidateResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) HashData(call kalkancrypt.HashDataCall) (kalkancrypt.BufferResult, error) {
	if f.hashDataFunc != nil {
		return f.hashDataFunc(call)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) SignHash(call kalkancrypt.SignHashCall) (kalkancrypt.BufferResult, error) {
	if f.signHashFunc != nil {
		return f.signHashFunc(call)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) SignData(call kalkancrypt.SignDataCall) (kalkancrypt.BufferResult, error) {
	if f.signDataFunc != nil {
		return f.signDataFunc(call)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) SignXML(call kalkancrypt.SignXMLCall) (kalkancrypt.BufferResult, error) {
	if f.signXMLFunc != nil {
		return f.signXMLFunc(call)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) SignWSSE(call kalkancrypt.SignWSSECall) (kalkancrypt.BufferResult, error) {
	if f.signWSSEFunc != nil {
		return f.signWSSEFunc(call)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) VerifyData(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
	if f.verifyDataFunc != nil {
		return f.verifyDataFunc(call)
	}
	return kalkancrypt.VerifyResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) VerifyXML(call kalkancrypt.VerifyXMLCall) (kalkancrypt.BufferResult, error) {
	if f.verifyXMLFunc != nil {
		return f.verifyXMLFunc(call)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) GetCertFromXML(xml []byte, signID, capacity int) (kalkancrypt.BufferResult, error) {
	if f.getCertFromXMLFunc != nil {
		return f.getCertFromXMLFunc(xml, signID, capacity)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) GetSigAlgFromXML(xml []byte, capacity int) (kalkancrypt.BufferResult, error) {
	if f.getSigAlgFromXMLFunc != nil {
		return f.getSigAlgFromXMLFunc(xml, capacity)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) GetTimeFromSig(data []byte, flags, sigID int) (uint64, int64) {
	if f.getTimeFromSigFunc != nil {
		return f.getTimeFromSigFunc(data, flags, sigID)
	}
	return uint64(ErrorOK), 0
}
func (f *fakeNativeContext) GetCertFromCMS(call kalkancrypt.GetCertFromCMSCall) (kalkancrypt.BufferResult, error) {
	if f.getCertFromCMSFunc != nil {
		return f.getCertFromCMSFunc(call)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) SetTSAURL(value string) uint64 {
	if f.setTSAURLFunc != nil {
		return f.setTSAURLFunc(value)
	}

	return uint64(ErrorOK)
}
func (f *fakeNativeContext) SetProxy(kalkancrypt.ProxyCall) uint64 {
	return uint64(ErrorOK)
}
func (f *fakeNativeContext) ZipConVerify(zipFile string, flags, capacity int) (kalkancrypt.BufferResult, error) {
	if f.zipConVerifyFunc != nil {
		return f.zipConVerifyFunc(zipFile, flags, capacity)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}
func (f *fakeNativeContext) ZipConSign(call kalkancrypt.ZipConSignCall) uint64 {
	if f.zipConSignFunc != nil {
		return f.zipConSignFunc(call)
	}
	return uint64(ErrorOK)
}
func (f *fakeNativeContext) GetCertFromZipFile(call kalkancrypt.GetCertFromZipFileCall) (kalkancrypt.BufferResult, error) {
	if f.getCertFromZipFileFunc != nil {
		return f.getCertFromZipFileFunc(call)
	}
	return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
}

func repeatedBytes(value byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}
