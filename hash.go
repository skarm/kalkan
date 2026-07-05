package kalkan

import (
	"context"
	"fmt"

	"github.com/skarm/kalkan/ckalkan"
)

// HashAlgorithm selects the digest algorithm used by Hash.
type HashAlgorithm int

func (a HashAlgorithm) native() (ckalkan.HashAlgorithm, error) {
	switch a {
	case SHA256:
		return ckalkan.SHA256, nil
	case GOST95:
		return ckalkan.GOST95, nil
	case GOST2015_256:
		return ckalkan.GOST2015_256, nil
	case GOST2015_512:
		return ckalkan.GOST2015_512, nil
	default:
		return "", fmt.Errorf("%w: unknown hash algorithm %d", ErrInvalidInput, a)
	}
}

const (
	// SHA256 calculates a SHA-256 digest.
	SHA256 HashAlgorithm = iota
	// GOST95 calculates a GOST R 34.11-95 digest.
	GOST95
	// GOST2015_256 calculates a GOST R 34.11-2015 256-bit digest.
	GOST2015_256
	// GOST2015_512 calculates a GOST R 34.11-2015 512-bit digest.
	GOST2015_512
)

// HashRequest describes data to hash.
type HashRequest struct {
	// Algorithm selects the digest algorithm. The zero value is SHA256.
	Algorithm HashAlgorithm
	// Data is the input data. File sources are passed to KalkanCrypt as file
	// paths when the native library supports KC_IN_FILE for HashData.
	Data Source
}

// Digest is returned by Hash.
type Digest struct {
	// Algorithm is the algorithm used to calculate Data.
	Algorithm HashAlgorithm
	// Data contains the raw digest bytes.
	Data []byte
}

// SignHashRequest describes signing of an already calculated digest.
type SignHashRequest struct {
	// Alias selects a loaded key alias. Empty alias lets KalkanCrypt use its
	// default loaded key when the native library supports that behavior.
	Alias string
	// Digest contains the precomputed raw digest bytes to sign, not the original
	// payload.
	Digest []byte
	// DigestAlgorithm selects the algorithm that produced Digest. The zero value
	// is SHA256. Set it explicitly when signing GOST or other non-SHA256 digests
	// so the wrapper can reject length mismatches before native calls.
	DigestAlgorithm HashAlgorithm
	// Timestamp requests a TSA timestamp token.
	Timestamp bool
	// IncludeCertificate asks KalkanCrypt to embed the signing certificate in
	// the CMS container.
	IncludeCertificate bool
	// OutputFormat selects the CMS output representation. The zero value
	// returns raw DER CMS bytes.
	OutputFormat CMSOutputFormat
	// CertificateTimeCheck controls KalkanCrypt certificate-time validation while
	// signing the digest.
	CertificateTimeCheck CertificateTimeCheck
}

// Hash calculates a digest using KalkanCrypt.
func (c *Client) Hash(ctx context.Context, req HashRequest) (*Digest, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !req.Data.isSet() {
		return nil, fmt.Errorf("%w: hash data is required", ErrInvalidInput)
	}

	algorithm, err := req.Algorithm.native()
	if err != nil {
		return nil, err
	}

	if err := validateEncoding(req.Data.encoding); err != nil {
		return nil, err
	}

	if err := validateMemorySourceSize(req.Data, "hash data", c.configuredMaxInputSize()); err != nil {
		return nil, err
	}

	data, err := req.Data.bytesOrPath()
	if err != nil {
		return nil, err
	}

	flags := inputFlag(effectiveEncoding(req.Data, EncodingRaw), false)
	if req.Data.file {
		flags |= ckalkan.InFile
	}

	digest, err := withLockedLibraryResult(c, ctx, "Hash", func(native hashing) ([]byte, error) {
		return native.HashData(algorithm, flags, data)
	})
	if err != nil {
		return nil, err
	}

	return &Digest{Algorithm: req.Algorithm, Data: digest}, nil
}

// SignHash signs raw digest bytes and returns CMS output bytes. The default
// output format is raw DER CMS.
func (c *Client) SignHash(ctx context.Context, req SignHashRequest) (*CMS, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(req.Digest) == 0 {
		return nil, fmt.Errorf("%w: digest is empty", ErrInvalidInput)
	}

	if err := validateBytesSize(req.Digest, "digest", c.configuredMaxInputSize()); err != nil {
		return nil, err
	}

	if err := validateDigestLength(req.DigestAlgorithm, req.Digest); err != nil {
		return nil, err
	}

	outputFlags, err := cmsOutputFlag(req.OutputFormat)
	if err != nil {
		return nil, err
	}

	flags := ckalkan.SignCMS | outputFlags
	if req.Timestamp {
		flags |= ckalkan.WithTimestamp
	}

	if req.IncludeCertificate {
		flags |= ckalkan.WithCert
	}

	checkFlags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	flags |= checkFlags

	out, err := withLockedLibraryResult(c, ctx, "SignHash", func(native hashing) ([]byte, error) {
		return native.SignHash(req.Alias, flags, req.Digest)
	})
	if err != nil {
		return nil, err
	}

	return &CMS{Data: out}, nil
}

func validateDigestLength(algorithm HashAlgorithm, digest []byte) error {
	name, want, err := digestInfo(algorithm)
	if err != nil {
		return err
	}

	if len(digest) != want {
		return fmt.Errorf("%w: digest length for %s must be %d bytes, got %d", ErrInvalidInput, name, want, len(digest))
	}

	return nil
}

func digestInfo(algorithm HashAlgorithm) (string, int, error) {
	switch algorithm {
	case SHA256:
		return string(ckalkan.SHA256), 32, nil
	case GOST95:
		return string(ckalkan.GOST95), 32, nil
	case GOST2015_256:
		return string(ckalkan.GOST2015_256), 32, nil
	case GOST2015_512:
		return string(ckalkan.GOST2015_512), 64, nil
	default:
		return "", 0, fmt.Errorf("%w: unknown hash algorithm %d", ErrInvalidInput, algorithm)
	}
}
