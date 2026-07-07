package kalkan

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

type fakeNative struct {
	initFunc                func() error
	hashDataFunc            func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error)
	signHashFunc            func(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error)
	signDataFunc            func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error)
	verifyDataFunc          func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error)
	signXMLFunc             func(req ckalkan.SignXMLRequest) ([]byte, error)
	verifyXMLFunc           func(alias string, flags ckalkan.Flag, xml []byte) (string, error)
	signWSSEFunc            func(req ckalkan.SignWSSERequest) ([]byte, error)
	validateCertificateFunc func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error)
	exportCertStoreFunc     func(alias string, format ckalkan.CertFormat) ([]byte, error)
	certificateGetInfoFunc  func(cert []byte, prop ckalkan.CertProp) ([]byte, error)
	getCertFromCMSFunc      func(cms []byte, signID int, flags ckalkan.Flag) ([]byte, error)
	getTimeFromSigFunc      func(data []byte, flags ckalkan.Flag, sigID int) (time.Time, error)
	getCertFromXMLFunc      func(xml []byte, signID int) ([]byte, error)
	getSigAlgFromXMLFunc    func(xml []byte) (string, error)
	loadKeyStoreFunc        func(ckalkan.Store, string, string, string) error
	loadCertBufferFunc      func([]byte, ckalkan.CertFormat) error
	loadCertFileFunc        func(string, ckalkan.CertType) error
	zipConSignFunc          func(req ckalkan.ZipConSignRequest) error
	zipConVerifyFunc        func(zipFile string, flags ckalkan.Flag) (string, error)
	getCertFromZipFileFunc  func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error)
	setTSAURLFunc           func(string) error
	setProxyFunc            func(ckalkan.ProxyRequest) error
	closeFunc               func() error
}

func (f *fakeNative) Init() error {
	if f.initFunc != nil {
		return f.initFunc()
	}
	return nil
}

func (f *fakeNative) Close() error {
	if f.closeFunc != nil {
		return f.closeFunc()
	}
	return nil
}

func (f *fakeNative) HashData(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
	if f.hashDataFunc == nil {
		return nil, errors.New("unexpected HashData call")
	}
	return f.hashDataFunc(algorithm, flags, data)
}

func (f *fakeNative) SignHash(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error) {
	if f.signHashFunc == nil {
		return nil, errors.New("unexpected SignHash call")
	}
	return f.signHashFunc(alias, flags, hash)
}

func (f *fakeNative) SignData(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
	if f.signDataFunc == nil {
		return nil, errors.New("unexpected SignData call")
	}
	return f.signDataFunc(alias, flags, data, signature)
}

func (f *fakeNative) VerifyData(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
	if f.verifyDataFunc == nil {
		return ckalkan.VerifyDataResult{}, errors.New("unexpected VerifyData call")
	}
	return f.verifyDataFunc(req)
}

func (f *fakeNative) SignXML(req ckalkan.SignXMLRequest) ([]byte, error) {
	if f.signXMLFunc == nil {
		return nil, errors.New("unexpected SignXML call")
	}
	return f.signXMLFunc(req)
}

func (f *fakeNative) VerifyXML(alias string, flags ckalkan.Flag, xml []byte) (string, error) {
	if f.verifyXMLFunc == nil {
		return "", errors.New("unexpected VerifyXML call")
	}
	return f.verifyXMLFunc(alias, flags, xml)
}

func (f *fakeNative) SignWSSE(req ckalkan.SignWSSERequest) ([]byte, error) {
	if f.signWSSEFunc == nil {
		return nil, errors.New("unexpected SignWSSE call")
	}
	return f.signWSSEFunc(req)
}

func (f *fakeNative) X509ValidateCertificate(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
	if f.validateCertificateFunc == nil {
		return ckalkan.ValidateCertificateResult{}, errors.New("unexpected X509ValidateCertificate call")
	}
	return f.validateCertificateFunc(req)
}

func (f *fakeNative) X509ExportCertificateFromStore(alias string, format ckalkan.CertFormat) ([]byte, error) {
	if f.exportCertStoreFunc == nil {
		return nil, errors.New("unexpected X509ExportCertificateFromStore call")
	}
	return f.exportCertStoreFunc(alias, format)
}

func (f *fakeNative) X509CertificateGetInfo(cert []byte, prop ckalkan.CertProp) ([]byte, error) {
	if f.certificateGetInfoFunc == nil {
		return nil, errors.New("unexpected X509CertificateGetInfo call")
	}
	return f.certificateGetInfoFunc(cert, prop)
}

func (f *fakeNative) GetCertFromCMS(cms []byte, signID int, flags ckalkan.Flag) ([]byte, error) {
	if f.getCertFromCMSFunc == nil {
		return nil, errors.New("unexpected GetCertFromCMS call")
	}
	return f.getCertFromCMSFunc(cms, signID, flags)
}

func (f *fakeNative) GetTimeFromSig(data []byte, flags ckalkan.Flag, sigID int) (time.Time, error) {
	if f.getTimeFromSigFunc == nil {
		return time.Time{}, errors.New("unexpected GetTimeFromSig call")
	}
	return f.getTimeFromSigFunc(data, flags, sigID)
}

func (f *fakeNative) GetCertFromXML(xml []byte, signID int) ([]byte, error) {
	if f.getCertFromXMLFunc == nil {
		return nil, errors.New("unexpected GetCertFromXML call")
	}
	return f.getCertFromXMLFunc(xml, signID)
}

func (f *fakeNative) GetSigAlgFromXML(xml []byte) (string, error) {
	if f.getSigAlgFromXMLFunc == nil {
		return "", errors.New("unexpected GetSigAlgFromXML call")
	}
	return f.getSigAlgFromXMLFunc(xml)
}

func (f *fakeNative) LoadKeyStore(storage ckalkan.Store, password, container, alias string) error {
	if f.loadKeyStoreFunc != nil {
		return f.loadKeyStoreFunc(storage, password, container, alias)
	}
	return errors.New("unexpected LoadKeyStore call")
}

func (f *fakeNative) X509LoadCertificateFromBuffer(cert []byte, format ckalkan.CertFormat) error {
	if f.loadCertBufferFunc != nil {
		return f.loadCertBufferFunc(cert, format)
	}
	return errors.New("unexpected X509LoadCertificateFromBuffer call")
}

func (f *fakeNative) X509LoadCertificateFromFile(path string, certType ckalkan.CertType) error {
	if f.loadCertFileFunc != nil {
		return f.loadCertFileFunc(path, certType)
	}
	return errors.New("unexpected X509LoadCertificateFromFile call")
}

func (f *fakeNative) SetTSAURL(tsaURL string) error {
	if f.setTSAURLFunc != nil {
		return f.setTSAURLFunc(tsaURL)
	}
	return nil
}

func (f *fakeNative) SetProxy(req ckalkan.ProxyRequest) error {
	if f.setProxyFunc != nil {
		return f.setProxyFunc(req)
	}
	return errors.New("unexpected SetProxy call")
}

func (f *fakeNative) ZipConSign(req ckalkan.ZipConSignRequest) error {
	if f.zipConSignFunc != nil {
		return f.zipConSignFunc(req)
	}
	return errors.New("unexpected ZipConSign call")
}

func (f *fakeNative) ZipConVerify(zipFile string, flags ckalkan.Flag) (string, error) {
	if f.zipConVerifyFunc != nil {
		return f.zipConVerifyFunc(zipFile, flags)
	}
	return "", errors.New("unexpected ZipConVerify call")
}

func (f *fakeNative) GetCertFromZipFile(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
	if f.getCertFromZipFileFunc != nil {
		return f.getCertFromZipFileFunc(zipFile, flags, signID)
	}
	return nil, errors.New("unexpected GetCertFromZipFile call")
}

func writeTestFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func sameByteSliceBacking(left, right []byte) bool {
	if len(left) == 0 || len(right) == 0 {
		return len(left) == len(right)
	}

	return &left[0] == &right[0]
}

func testLibraryPath() string {
	if runtime.GOOS == "windows" {
		return `C:\kalkan\KalkanCrypt.dll`
	}

	return "/opt/kalkan/libkalkancryptwr-64.so"
}

func TestTestLibraryPathIsAbsoluteOnCurrentPlatform(t *testing.T) {
	if !filepath.IsAbs(testLibraryPath()) {
		t.Fatalf("testLibraryPath() = %q, want platform-absolute path", testLibraryPath())
	}
}

func signerIDOverflowValue(t *testing.T) int {
	t.Helper()
	if strconv.IntSize <= 32 {
		t.Skip("SignerID overflow value is not representable as int on this platform")
	}

	return int(int64(maxSignerID) + 1)
}
