package kalkan

import (
	"context"
	"errors"
	"fmt"

	"github.com/skarm/kalkan/ckalkan"
)

// SignZIPRequest describes signing a file into a KalkanCrypt ZIP container.
type SignZIPRequest struct {
	// Alias selects a loaded key alias. Empty alias lets KalkanCrypt use its
	// default loaded key when the native library supports that behavior.
	Alias string
	// InputPath is the input file path passed to KalkanCrypt.
	InputPath string
	// OutputPath is the expected ZIP container path and must end with .zip,
	// matched case-insensitively. KalkanCrypt creates lowercase .zip output, so
	// non-lowercase extensions are accepted but SignedZIP.Path reports the
	// actual lowercase path.
	// Use a private service-controlled output directory: KalkanCrypt writes the
	// output file itself, so this wrapper rejects a pre-existing output but
	// cannot make the native create operation atomically exclusive.
	OutputPath string
	// CertificateTimeCheck controls KalkanCrypt certificate-time validation while
	// building the ZIP signature.
	CertificateTimeCheck CertificateTimeCheck
}

// SignedZIP is returned by SignZIP.
type SignedZIP struct {
	// Path is the ZIP container path created by KalkanCrypt.
	Path string
}

// VerifyZIPRequest describes ZIP signature verification.
type VerifyZIPRequest struct {
	// Path is the ZIP container path passed to KalkanCrypt.
	Path string
	// SignerID selects a signer certificate from multi-signer containers when
	// ReturnSignerCertificate is true.
	SignerID int
	// ReturnSignerCertificate asks VerifyZIP to also extract the selected signer
	// certificate after successful ZIP verification.
	ReturnSignerCertificate bool
	// CertificateTimeCheck controls KalkanCrypt certificate-time validation.
	CertificateTimeCheck CertificateTimeCheck
}

// ZIPVerification is returned by VerifyZIP.
type ZIPVerification struct {
	// Valid is always true when err is nil. Invalid ZIP signatures are returned
	// as errors; the field is kept for readability and future compatibility.
	Valid bool
	// Info is KalkanCrypt's native ZIP verification information string.
	Info string
	// SignerCert contains the selected signer certificate when requested.
	SignerCert []byte
}

// ZIPSignerCertificateRequest describes signer-certificate extraction from a
// ZIP container.
type ZIPSignerCertificateRequest struct {
	// Path is the ZIP container path passed to KalkanCrypt.
	Path string
	// SignerID selects a signer certificate from multi-signer containers.
	SignerID int
	// CertificateTimeCheck controls KalkanCrypt certificate-time validation.
	CertificateTimeCheck CertificateTimeCheck
}

// SignZIP signs InputPath and creates a KalkanCrypt ZIP container at OutputPath.
func (c *Client) SignZIP(ctx context.Context, req SignZIPRequest) (*SignedZIP, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	inputPath, err := validateNativePathString("ZIP input file path", req.InputPath)
	if err != nil {
		return nil, err
	}

	plan, err := zipOutputPlan(req.OutputPath)
	if err != nil {
		return nil, err
	}

	checkFlags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	if err := ensureZIPOutputAbsent(plan); err != nil {
		return nil, err
	}

	if err := withLockedLibrary(c, ctx, "SignZIP", func(native zipContainers) error {
		if err := ensureZIPOutputAbsent(plan); err != nil {
			return err
		}

		return native.ZipConSign(ckalkan.ZipConSignRequest{
			Alias:    req.Alias,
			FilePath: inputPath,
			Name:     plan.nativeName,
			OutDir:   plan.outDir,
			Flags:    checkFlags,
		})
	}); err != nil {
		return nil, err
	}

	path, err := createdZIPPath(plan)
	if err != nil {
		if cleanupErr := cleanupZIPOutput(plan); cleanupErr != nil {
			return nil, errors.Join(err, cleanupErr)
		}

		return nil, err
	}

	return &SignedZIP{Path: path}, nil
}

// VerifyZIP verifies a KalkanCrypt ZIP container.
func (c *Client) VerifyZIP(ctx context.Context, req VerifyZIPRequest) (*ZIPVerification, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	zipPath, err := validateNativePathString("ZIP path", req.Path)
	if err != nil {
		return nil, err
	}

	if err := validateSignerID("SignerID", req.SignerID); err != nil {
		return nil, err
	}

	flags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	nativeResult, err := withLockedLibraryResult(c, ctx, "VerifyZIP", func(native zipContainers) (zipVerificationNativeResult, error) {
		info, err := native.ZipConVerify(zipPath, flags)
		if err != nil {
			return zipVerificationNativeResult{}, err
		}

		var cert []byte
		if req.ReturnSignerCertificate {
			cert, err = native.GetCertFromZipFile(zipPath, flags, req.SignerID)
			if err != nil {
				return zipVerificationNativeResult{}, err
			}

			if isEmptyNativeCertificate(cert) {
				return zipVerificationNativeResult{}, fmt.Errorf("%w: ZIP signer certificate output is empty", ErrInvalidInput)
			}
		}

		return zipVerificationNativeResult{info: info, cert: cert}, nil
	})
	if err != nil {
		return nil, err
	}

	return &ZIPVerification{
		Valid:      true,
		Info:       nativeResult.info,
		SignerCert: nativeResult.cert,
	}, nil
}

// ZIPSignerCertificate extracts a signer certificate from a KalkanCrypt ZIP container.
func (c *Client) ZIPSignerCertificate(ctx context.Context, req ZIPSignerCertificateRequest) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	zipPath, err := validateNativePathString("ZIP path", req.Path)
	if err != nil {
		return nil, err
	}

	if err := validateSignerID("SignerID", req.SignerID); err != nil {
		return nil, err
	}

	flags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	cert, err := withLockedLibraryResult(c, ctx, "ZIPSignerCertificate", func(native zipContainers) ([]byte, error) {
		return native.GetCertFromZipFile(zipPath, flags, req.SignerID)
	})
	if err != nil {
		return nil, err
	}

	if isEmptyNativeCertificate(cert) {
		return nil, fmt.Errorf("%w: ZIP signer certificate output is empty", ErrInvalidInput)
	}

	return cert, nil
}

type zipPlan struct {
	requestedPath string
	desiredPath   string
	nativeName    string
	outDir        string
}

type zipVerificationNativeResult struct {
	info string
	cert []byte
}
