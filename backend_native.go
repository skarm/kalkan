package kalkan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/skarm/kalkan/ckalkan"
)

// nativeBackend retains trusted certificates for reload after LoadKeyStore.
// All methods run while the client call gate is held.
type nativeBackend struct {
	sdk     io.Closer
	trusted []trustedCertificate
}

func newNativeBackend(sdk io.Closer) *nativeBackend {
	return &nativeBackend{sdk: sdk}
}

func (c *config) validateLibraryPath() error {
	libraryPath, err := validateNativePathString("library path", c.libraryPath)
	if err != nil {
		if c.libraryPath == "" {
			return fmt.Errorf("%w: library path is required", ErrInvalidInput)
		}

		return err
	}

	if !filepath.IsAbs(libraryPath) {
		return fmt.Errorf("%w: absolute library path is required", ErrInvalidInput)
	}

	c.libraryPath = libraryPath

	return nil
}

func openNativeBackend(cfg config) (backend, error) {
	options := []ckalkan.Option{ckalkan.WithLibrary(cfg.libraryPath)}
	if cfg.maxOutputBufferSize > 0 {
		options = append(options, ckalkan.WithMaxBufferSize(cfg.maxOutputBufferSize))
	}

	sdk, err := ckalkan.New(options...)
	if err != nil {
		if errors.Is(err, ckalkan.ErrUnavailable) {
			return nil, ErrUnavailable
		}

		return nil, err
	}

	return newNativeBackend(sdk), nil
}

func (b *nativeBackend) WithContext(context.Context) any {
	return b.sdk
}

func (*nativeBackend) NormalizeError(err error) error {
	return err
}

func (b *nativeBackend) Close() error {
	err := b.sdk.Close()
	b.trusted = nil

	return err
}

func (b *nativeBackend) LoadKeyStore(_ context.Context, storage ckalkan.Store, password, container, alias string) error {
	native, ok := b.sdk.(keyStoreLoader)
	if !ok {
		return unsupportedOperation("LoadKeyStore")
	}

	if err := native.LoadKeyStore(storage, password, container, alias); err != nil {
		return err
	}

	// Restore trust under the same call gate, including after cancellation.
	return b.restoreTrustedCertificates()
}

func (b *nativeBackend) LoadTrustedCertificate(_ context.Context, cert trustedCertificate) error {
	native, ok := b.sdk.(certificateOperations)
	if !ok {
		return unsupportedOperation("LoadTrustedCertificate")
	}

	if err := loadNativeTrustedCertificate(native, cert); err != nil {
		return err
	}

	b.rememberTrustedCertificate(cert)

	return nil
}

func loadNativeTrustedCertificate(native certificateOperations, cert trustedCertificate) error {
	if cert.path != "" {
		return native.X509LoadCertificateFromFile(cert.path, cert.certType)
	}

	return native.X509LoadCertificateFromBuffer(cert.data, cert.format)
}

func (b *nativeBackend) rememberTrustedCertificate(cert trustedCertificate) {
	for _, previous := range b.trusted {
		if cert.path == previous.path && cert.certType == previous.certType &&
			cert.format == previous.format && bytes.Equal(cert.data, previous.data) {
			return
		}
	}

	cert.data = bytes.Clone(cert.data)
	b.trusted = append(b.trusted, cert)
}

func (b *nativeBackend) restoreTrustedCertificates() error {
	if len(b.trusted) == 0 {
		return nil
	}

	native, ok := b.sdk.(certificateOperations)
	if !ok {
		return fmt.Errorf("kalkan: key store loaded but restoring trusted certificates failed: %w", unsupportedOperation("LoadTrustedCertificate"))
	}

	for index, cert := range b.trusted {
		if err := loadNativeTrustedCertificate(native, cert); err != nil {
			return fmt.Errorf("kalkan: key store loaded but restoring trusted certificate %d failed: %w", index+1, err)
		}
	}

	return nil
}
