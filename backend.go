package kalkan

import (
	"context"
	"fmt"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

// backend owns the SDK session and its trusted certificates.
// WithContext returns operations used while the client call gate is held.
type backend interface {
	Close() error
	WithContext(context.Context) any
	NormalizeError(error) error
	LoadKeyStore(context.Context, ckalkan.Store, string, string, string) error
	LoadTrustedCertificate(context.Context, trustedCertificate) error
}

type trustedCertificate struct {
	data     []byte
	path     string
	certType ckalkan.CertType
	format   ckalkan.CertFormat
}

type sessionInitializer interface {
	Init() error
}

type networkSettings interface {
	SetTSAURL(tsaURL string) error
	SetProxy(req ckalkan.ProxyRequest) error
}

type hashOperations interface {
	HashData(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error)
	SignHash(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error)
}

type cmsOperations interface {
	SignData(req ckalkan.SignDataRequest) ([]byte, error)
	VerifyData(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error)
	GetCertFromCMS(data []byte, signID int, flags ckalkan.Flag) ([]byte, error)
	GetTimeFromSig(data []byte, flags ckalkan.Flag, sigID int) (time.Time, error)
}

type xmlOperations interface {
	SignXML(req ckalkan.SignXMLRequest) ([]byte, error)
	VerifyXML(alias string, flags ckalkan.Flag, xml []byte) (string, error)
	SignWSSE(req ckalkan.SignWSSERequest) ([]byte, error)
	GetCertFromXML(xml []byte, signID int) ([]byte, error)
	GetSigAlgFromXML(xml []byte) (string, error)
}

type certificateOperations interface {
	X509ValidateCertificate(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error)
	X509ExportCertificateFromStore(alias string, format ckalkan.CertFormat) ([]byte, error)
	X509CertificateGetInfo(cert []byte, prop ckalkan.CertProp) ([]byte, error)
	X509LoadCertificateFromBuffer(cert []byte, format ckalkan.CertFormat) error
	X509LoadCertificateFromFile(certPath string, certType ckalkan.CertType) error
}

type keyStoreLoader interface {
	LoadKeyStore(storage ckalkan.Store, password, container, alias string) error
}

type zipOperations interface {
	ZipConSign(req ckalkan.ZipConSignRequest) error
	ZipConVerify(zipFile string, flags ckalkan.Flag) (string, error)
	GetCertFromZipFile(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error)
}

type backendFactory func(config) (backend, error)

func openBackend(cfg config) (backend, error) {
	if cfg.java.providerPath != "" {
		return newJavaBackend(cfg), nil
	}

	return openNativeBackend(cfg)
}

func (c *config) validateBackend() error {
	if c.java.providerPath != "" {
		if c.libraryPath != "" {
			return fmt.Errorf("%w: choose either WithLibraryPath or WithJavaProvider", ErrInvalidInput)
		}

		return c.java.validate(c.maxOutputBufferSize)
	}

	if err := c.java.requireProvider(); err != nil {
		return err
	}

	return c.validateLibraryPath()
}

func (c *config) startupEndpointPolicy() *EndpointPolicy {
	if c.java.providerPath != "" {
		// Java validates each actual request, including certificate-derived URLs.
		return nil
	}

	return c.endpointPolicy
}
