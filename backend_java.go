package kalkan

import (
	"context"
	"errors"
	"slices"

	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/internal/javakalkan"
)

// javaBackend owns a Java worker and translates its input errors.
type javaBackend struct {
	client *javakalkan.Client
}

func newJavaBackend(cfg config) *javaBackend {
	limit := cfg.maxOutputBufferSize
	if limit == 0 {
		limit = DefaultMaxOutputBufferSize
	}

	mode, source := "ocsp", cfg.ocspURL
	if cfg.java.revocation != nil {
		source = cfg.java.revocation.source
		switch cfg.java.revocation.mode {
		case CertificateValidationNone:
			mode = "none"
		case CertificateValidationCRL:
			mode = "crl"
		case CertificateValidationOCSP:
			if source == "" {
				source = cfg.ocspURL
			}
		}
	}

	policy := cloneEndpointPolicy(cfg.endpointPolicy)
	client := javakalkan.New(javakalkan.Config{
		ProviderPath:     cfg.java.providerPath,
		Executable:       cfg.java.executable,
		XMLLibraries:     slices.Clone(cfg.java.xmlLibraries),
		MaxInputSize:     cfg.maxInputSize,
		MaxOutputSize:    limit,
		RevocationMode:   mode,
		RevocationSource: source,
		ValidateURL: func(raw string) (string, error) {
			return normalizeNativeHTTPURLWithPolicy("Java validation URL", raw, "revocation", policy)
		},
	})

	return &javaBackend{client: client}
}

func (b *javaBackend) Close() error { return b.client.Close() }

func (b *javaBackend) WithContext(ctx context.Context) any { return b.client.WithContext(ctx) }

func (*javaBackend) NormalizeError(err error) error {
	if errors.Is(err, javakalkan.ErrInvalidInput) {
		return errors.Join(ErrInvalidInput, err)
	}

	return err
}

func (b *javaBackend) LoadKeyStore(ctx context.Context, storage ckalkan.Store, password, container, alias string) error {
	return b.client.WithContext(ctx).LoadKeyStore(storage, password, container, alias)
}

func (b *javaBackend) LoadTrustedCertificate(ctx context.Context, cert trustedCertificate) error {
	operation := b.client.WithContext(ctx)
	if cert.path != "" {
		return operation.X509LoadCertificateFromFile(cert.path, cert.certType)
	}

	return operation.X509LoadCertificateFromBuffer(cert.data, cert.format)
}
