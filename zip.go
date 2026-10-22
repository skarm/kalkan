package kalkan

import (
	"context"
	"fmt"

	"github.com/skarm/kalkan/ckalkan"
)

// SignZIPRequest describes a request to create a KalkanCrypt ZIP container
// from an input path.
type SignZIPRequest struct {
	// Alias selects a loaded key alias. Empty alias lets KalkanCrypt use its
	// default loaded key when the native library supports that behavior.
	Alias string
	// InputPath identifies the input that the client passes unchanged to KalkanCrypt.
	// The Linux native adapter requires an existing directory.
	// It returns ckalkan.ErrorParam for other input types before the SDK can
	// create an empty container for a regular file.
	//
	// Keep the input files unchanged until SignZIP returns.
	// Create output outside the input directory.
	InputPath string
	// OutputPath is the expected ZIP container path.
	// Its extension must match .zip without case sensitivity.
	// KalkanCrypt creates a lowercase .zip extension.
	// SignedZIP.Path reports the actual output path.
	//
	// The path must not exist.
	// Enable [WithAtomicZIPOutput] for atomic publication without replacement of
	// an existing destination.
	// The default native path has no atomic create-if-absent guarantee.
	OutputPath string
	// CertificateTimeCheck controls native certificate-time validation for the
	// ZIP signature.
	CertificateTimeCheck CertificateTimeCheck
}

// SignedZIP identifies the container created by [Client.SignZIP]. Path records
// the actual output path, including the extension chosen by the native signer.
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

// SignZIP creates a signed ZIP container from req.InputPath.
// The result contains the actual output path.
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

	activePlan := plan
	atomicOutput := c != nil && c.config.atomicZIPOutput

	if atomicOutput {
		var cleanup func()

		activePlan, cleanup, err = stagedZIPOutputPlan(plan)
		if err != nil {
			return nil, err
		}
		defer cleanup()
	}

	if err := withLockedLibrary(c, ctx, "SignZIP", func(native zipContainers) error {
		if err := ensureZIPOutputAbsent(activePlan); err != nil {
			return err
		}

		return native.ZipConSign(ckalkan.ZipConSignRequest{
			Alias:    req.Alias,
			FilePath: inputPath,
			Name:     activePlan.nativeName,
			OutDir:   activePlan.outDir,
			Flags:    checkFlags,
		})
	}); err != nil {
		return nil, err
	}

	path, err := createdZIPPath(activePlan)
	if err != nil {
		return nil, err
	}

	if atomicOutput {
		path, err = publishStagedZIP(path, plan)
		if err != nil {
			return nil, err
		}
	}

	return &SignedZIP{Path: path}, nil
}

// VerifyZIP verifies the ZIP container at req.Path and returns native
// diagnostics.
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

// ExtractZIPSignerCertificate returns bytes for signer req.SignerID from the
// ZIP container at req.Path.
// It does not verify the ZIP signature.
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
