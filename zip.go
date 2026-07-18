package kalkan

import (
	"context"
	"fmt"

	"github.com/skarm/kalkan/ckalkan"
)

// SignZIPRequest describes signing a file into a KalkanCrypt ZIP container.
type SignZIPRequest struct {
	// Alias selects a loaded key alias. Empty alias lets KalkanCrypt use its
	// default loaded key when the native library supports that behavior.
	Alias string
	// InputPath is passed unchanged to KalkanCrypt. Keep the referenced file
	// unchanged until SignZIP returns.
	InputPath string
	// OutputPath is the expected ZIP container path and must end with .zip,
	// matched case-insensitively. KalkanCrypt creates lowercase .zip output, so
	// non-lowercase extensions are accepted but SignedZIP.Path reports the
	// actual lowercase path.
	// The path must not exist. KalkanCrypt creates it without an atomic
	// create-if-absent guarantee.
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
	// Path is passed unchanged to KalkanCrypt. Keep the referenced file unchanged
	// until VerifyZIP returns.
	Path string
	// CertificateTimeCheck controls KalkanCrypt certificate-time validation.
	CertificateTimeCheck CertificateTimeCheck
}

// ExtractZIPSignerCertificateRequest describes signer-certificate extraction
// from a ZIP container.
type ExtractZIPSignerCertificateRequest struct {
	// Path is passed unchanged to KalkanCrypt. Keep the referenced file unchanged
	// until ExtractZIPSignerCertificate returns.
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

	if err := rejectEmbeddedNUL("alias", req.Alias); err != nil {
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
		return nil, err
	}

	return &SignedZIP{Path: path}, nil
}

// VerifyZIP verifies a KalkanCrypt ZIP container.
func (c *Client) VerifyZIP(ctx context.Context, req VerifyZIPRequest) (*Verification, error) {
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

	flags, err := certificateTimeCheckFlag(req.CertificateTimeCheck)
	if err != nil {
		return nil, err
	}

	info, err := withLockedLibraryResult(c, ctx, "VerifyZIP", func(native zipContainers) (string, error) {
		return native.ZipConVerify(zipPath, flags)
	})
	if err != nil {
		return nil, err
	}

	return &Verification{
		Info: info,
	}, nil
}

// ExtractZIPSignerCertificate extracts a signer certificate without verifying
// the ZIP signature.
func (c *Client) ExtractZIPSignerCertificate(ctx context.Context, req ExtractZIPSignerCertificateRequest) ([]byte, error) {
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

	cert, err := withLockedLibraryResult(c, ctx, "ExtractZIPSignerCertificate", func(native zipContainers) ([]byte, error) {
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
