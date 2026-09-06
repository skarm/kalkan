package kalkan

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/skarm/kalkan/ckalkan"
)

// KeyStoreType identifies a KalkanCrypt key storage provider.
type KeyStoreType int

func (t KeyStoreType) native() (ckalkan.Store, error) {
	switch t {
	case PKCS12:
		return ckalkan.StorePKCS12, nil
	default:
		return 0, fmt.Errorf("%w: unknown key store type %d", ErrInvalidInput, t)
	}
}

const (
	// PKCS12 loads a file-system PKCS#12 container.
	PKCS12 KeyStoreType = iota
)

// KeyStore describes a private-key container to load into KalkanCrypt.
// Type defaults to [PKCS12]; Path must name a container and cannot be empty.
type KeyStore struct {
	// Type selects the storage provider.
	Type KeyStoreType
	// Path is the native container path.
	Path string
	// Password is the container password.
	Password string
	// Alias optionally selects a key alias inside the container.
	Alias string
}

// TrustedCertificate describes a certificate loaded into KalkanCrypt's trust
// store. Set either a nonempty Path or nonempty Data. A zero value is invalid.
type TrustedCertificate struct {
	// Data contains certificate bytes when Path is empty. The bytes are borrowed
	// for the initial load; after success the client retains its own copy for
	// restoration after LoadKeyStore. Keep Data unchanged until loading returns.
	Data []byte
	// Path is loaded directly by KalkanCrypt when set. The file and its contents
	// must remain available and unchanged for restoration after every successful
	// LoadKeyStore.
	Path string
	// Type selects CA, intermediate, or user certificate role for Path.
	// It is validated for both sources, but the SDK buffer-loading function
	// receives only Data and Format and has no role parameter.
	Type CertificateType
	// Format selects PEM, DER, or base64 bytes for Data.
	Format CertificateFormat
}

type loadedTrustedCertificate struct {
	data     []byte
	path     string
	certType ckalkan.CertType
	format   ckalkan.CertFormat
}

func (cert loadedTrustedCertificate) load(native certificates) error {
	if cert.path != "" {
		return native.X509LoadCertificateFromFile(cert.path, cert.certType)
	}

	return native.X509LoadCertificateFromBuffer(cert.data, cert.format)
}

// rememberTrustedCertificate retains only successfully loaded certificates.
// The caller must hold the native call gate.
func (c *Client) rememberTrustedCertificate(cert loadedTrustedCertificate) {
	for _, previous := range c.trusted {
		if cert.path == previous.path && cert.certType == previous.certType &&
			cert.format == previous.format && bytes.Equal(cert.data, previous.data) {
			return
		}
	}

	cert.data = bytes.Clone(cert.data)
	c.trusted = append(c.trusted, cert)
}

// restoreTrustedCertificates must run inside the successful key-store load's
// native call gate, including if its context has since been canceled.
func (c *Client) restoreTrustedCertificates(native keyStore) error {
	if len(c.trusted) == 0 {
		return nil
	}

	loader, ok := native.(certificates)
	if !ok {
		return fmt.Errorf("kalkan: key store loaded but restoring trusted certificates failed: %w", unsupportedLibraryCapability("LoadTrustedCertificate"))
	}

	for index, cert := range c.trusted {
		if err := cert.load(loader); err != nil {
			return fmt.Errorf("kalkan: key store loaded but restoring trusted certificate %d failed: %w", index+1, err)
		}
	}

	return nil
}

// CertificateType identifies a certificate role in KalkanCrypt's store.
type CertificateType int

func (t CertificateType) native() (ckalkan.CertType, error) {
	switch t {
	case CertificateCA:
		return ckalkan.CertCA, nil
	case CertificateIntermediate:
		return ckalkan.CertIntermediate, nil
	case CertificateUser:
		return ckalkan.CertUser, nil
	default:
		return 0, fmt.Errorf("%w: unknown certificate type %d", ErrInvalidInput, t)
	}
}

func (f CertificateFormat) native() (ckalkan.CertFormat, error) {
	switch f {
	case CertificateDER:
		return ckalkan.CertDER, nil
	case CertificatePEM:
		return ckalkan.CertPEM, nil
	case CertificateBase64:
		return ckalkan.CertB64, nil
	default:
		return 0, fmt.Errorf("%w: unknown certificate format %d", ErrInvalidInput, f)
	}
}

const (
	// CertificateCA marks a root CA certificate.
	CertificateCA CertificateType = iota
	// CertificateIntermediate marks an intermediate CA certificate.
	CertificateIntermediate
	// CertificateUser marks a user certificate.
	CertificateUser
)

// CertificateFormat identifies certificate byte encoding.
type CertificateFormat int

const (
	// CertificateDER is DER binary certificate data.
	CertificateDER CertificateFormat = iota
	// CertificatePEM is PEM text certificate data.
	CertificatePEM
	// CertificateBase64 is base64 certificate data.
	CertificateBase64
)

// Proxy configures KalkanCrypt's native HTTP proxy.
// Its zero value disables proxy use; the remaining fields are ignored when
// Enabled is false.
type Proxy struct {
	// Enabled enables or disables proxy use.
	Enabled bool
	// Address is the proxy host or IP address.
	Address string
	// Port is the proxy port.
	Port string
	// User is the optional proxy username.
	User string
	// Password is the optional proxy password.
	Password string
}

func (p Proxy) validate() error {
	if !p.Enabled {
		return nil
	}

	address := strings.TrimSpace(p.Address)
	if address == "" {
		return fmt.Errorf("%w: proxy address is empty", ErrInvalidInput)
	}

	if err := rejectEmbeddedNUL("proxy address", address); err != nil {
		return err
	}

	if strings.ContainsFunc(address, unicode.IsSpace) {
		return fmt.Errorf("%w: proxy address contains whitespace", ErrInvalidInput)
	}

	port := strings.TrimSpace(p.Port)
	if port == "" {
		return fmt.Errorf("%w: proxy port is empty", ErrInvalidInput)
	}

	if err := rejectEmbeddedNUL("proxy port", port); err != nil {
		return err
	}

	number, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("%w: proxy port must be a number: %w", ErrInvalidInput, err)
	}

	if number < 1 || number > 65535 {
		return fmt.Errorf("%w: proxy port must be in range 1..65535", ErrInvalidInput)
	}

	if err := rejectEmbeddedNUL("proxy user", p.User); err != nil {
		return err
	}

	if err := rejectEmbeddedNUL("proxy password", p.Password); err != nil {
		return err
	}

	return nil
}

func (p Proxy) native() ckalkan.ProxyRequest {
	flags := ckalkan.ProxyOff
	if !p.Enabled {
		return ckalkan.ProxyRequest{Flags: flags}
	}

	flags = ckalkan.ProxyOn

	if p.User != "" || p.Password != "" {
		flags |= ckalkan.ProxyAuth
	}

	return ckalkan.ProxyRequest{
		Flags:    flags,
		Address:  strings.TrimSpace(p.Address),
		Port:     strings.TrimSpace(p.Port),
		User:     p.User,
		Password: p.Password,
	}
}

// LoadKeyStore loads a key container into the native KalkanCrypt session.
// After a successful native load, it restores all trusted certificates loaded
// through this client before allowing another operation to run. If restoration
// fails, the error reports partial success: the key store has already changed,
// and a later LoadKeyStore retries restoration from the retained certificates.
// Callers using different key stores must externally synchronize the entire
// load-and-sign sequence; the client serializes individual calls only.
func (c *Client) LoadKeyStore(ctx context.Context, store KeyStore) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	storage, err := store.Type.native()
	if err != nil {
		return err
	}

	path := store.Path

	path, err = validateNativePathString("key store path", path)
	if err != nil {
		return err
	}

	if err := rejectEmbeddedNUL("key store password", store.Password); err != nil {
		return err
	}

	if err := rejectEmbeddedNUL("key store alias", store.Alias); err != nil {
		return err
	}

	return withLockedLibrary(c, ctx, "LoadKeyStore", func(native keyStore) error {
		if err := native.LoadKeyStore(storage, store.Password, path, store.Alias); err != nil {
			return err
		}

		return c.restoreTrustedCertificates(native)
	})
}

// LoadTrustedCertificate loads a certificate into the native KalkanCrypt store.
// Successful loads are retained for restoration after LoadKeyStore until Close.
func (c *Client) LoadTrustedCertificate(ctx context.Context, cert TrustedCertificate) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	certType, err := cert.Type.native()
	if err != nil {
		return err
	}

	path := cert.Path
	if path != "" && len(cert.Data) != 0 {
		return fmt.Errorf("%w: trusted certificate must set either Path or Data, not both", ErrInvalidInput)
	}

	if path != "" {
		validatedPath, err := validateNativePathString("trusted certificate path", path)
		if err != nil {
			return err
		}

		return withLockedLibrary(c, ctx, "LoadTrustedCertificate", func(native certificates) error {
			loaded := loadedTrustedCertificate{path: validatedPath, certType: certType}
			if err := loaded.load(native); err != nil {
				return err
			}

			c.rememberTrustedCertificate(loaded)

			return nil
		})
	}

	if len(cert.Data) == 0 {
		return fmt.Errorf("%w: trusted certificate data is empty", ErrInvalidInput)
	}

	format, err := cert.Format.native()
	if err != nil {
		return err
	}

	if err := validateBytesSize(cert.Data, "trusted certificate data", c.configuredMaxInputSize()); err != nil {
		return err
	}

	return withLockedLibrary(c, ctx, "LoadTrustedCertificate", func(native certificates) error {
		// The buffer API has no role parameter, so its restoration identity
		// consists only of the bytes and format.
		loaded := loadedTrustedCertificate{data: cert.Data, format: format}
		if err := loaded.load(native); err != nil {
			return err
		}

		c.rememberTrustedCertificate(loaded)

		return nil
	})
}

// SetProxy configures KalkanCrypt's native HTTP proxy for the open session.
func (c *Client) SetProxy(ctx context.Context, proxy Proxy) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := proxy.validate(); err != nil {
		return err
	}

	return withLockedLibrary(c, ctx, "SetProxy", func(native network) error {
		return native.SetProxy(proxy.native())
	})
}
