package kalkan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestWithSDKFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadSDKAssets(t)
	client := openSDKClient(t, assets)

	if err := client.LoadKeyStore(ctx, KeyStore{
		Type:     PKCS12,
		Path:     sdkKeyStorePath(t, assets),
		Password: sdkPassword,
	}); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}

	payload := []byte("root kalkan API integration payload")

	t.Run("Hash", func(t *testing.T) {
		assertSDKHashing(t, ctx, client, payload)
	})

	t.Run("SignHash", func(t *testing.T) {
		assertSDKHashSigning(t, ctx, client, payload)
	})

	t.Run("CMS", func(t *testing.T) {
		assertSDKCMS(t, ctx, client, payload)
	})

	t.Run("XML", func(t *testing.T) {
		assertSDKXML(t, ctx, client, assets)
	})

	t.Run("WSSE", func(t *testing.T) {
		assertSDKWSSE(t, ctx, client, assets)
	})

	t.Run("CertificateValidation", func(t *testing.T) {
		assertSDKCertificateValidation(t, ctx, client, assets)
	})

	t.Run("ZIP", func(t *testing.T) {
		assertSDKZIP(t, ctx, client, assets, payload)
	})
}

func assertSDKHashing(t *testing.T, ctx context.Context, client *Client, payload []byte) {
	t.Helper()

	hash, err := client.Hash(ctx, HashRequest{
		Algorithm: SHA256,
		Data:      Bytes(payload),
	})
	if err != nil {
		t.Fatalf("Hash(SHA-256) failed: %v", err)
	}
	wantHash := sha256.Sum256(payload)
	if !bytes.Equal(hash.Data, wantHash[:]) {
		t.Fatalf("Hash(SHA-256) returned %x, want %x", hash.Data, wantHash)
	}

	hashFile := filepath.Join(t.TempDir(), "hash-payload.txt")
	if err := os.WriteFile(hashFile, payload, 0o644); err != nil {
		t.Fatalf("write hash payload: %v", err)
	}
	fileHash, err := client.Hash(ctx, HashRequest{
		Algorithm: SHA256,
		Data:      File(hashFile),
	})
	if err != nil {
		t.Fatalf("Hash(SHA-256 file) failed: %v", err)
	}
	if !bytes.Equal(fileHash.Data, wantHash[:]) {
		t.Fatalf("Hash(SHA-256 file) returned %x, want %x", fileHash.Data, wantHash)
	}

	for _, check := range []struct {
		name      string
		algorithm HashAlgorithm
		wantLen   int
	}{
		{name: "GOST 34.11-95", algorithm: GOST95, wantLen: 32},
		{name: "GOST 34.11-2015 256", algorithm: GOST2015_256, wantLen: 32},
		{name: "GOST 34.11-2015 512", algorithm: GOST2015_512, wantLen: 64},
	} {
		digest, err := client.Hash(ctx, HashRequest{
			Algorithm: check.algorithm,
			Data:      Bytes(payload),
		})
		if err != nil {
			t.Fatalf("Hash(%s) failed: %v", check.name, err)
		}
		if len(digest.Data) != check.wantLen {
			t.Fatalf("Hash(%s) returned %d bytes, want %d", check.name, len(digest.Data), check.wantLen)
		}
	}
}

func assertSDKHashSigning(t *testing.T, ctx context.Context, client *Client, payload []byte) {
	t.Helper()

	gost512, err := client.Hash(ctx, HashRequest{
		Algorithm: GOST2015_512,
		Data:      Bytes(payload),
	})
	if err != nil {
		t.Fatalf("Hash(GOST 34.11-2015 512) failed: %v", err)
	}
	signedHash, err := client.SignHash(ctx, SignHashRequest{
		Digest:               gost512.Data,
		DigestAlgorithm:      gost512.Algorithm,
		IncludeCertificate:   true,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignHash failed: %v", err)
	}
	if len(signedHash.Data) == 0 {
		t.Fatal("SignHash returned an empty CMS")
	}
}

func assertSDKCMS(t *testing.T, ctx context.Context, client *Client, payload []byte) {
	t.Helper()

	attached, err := client.SignCMS(ctx, SignCMSRequest{
		Data:                 Bytes(payload),
		IncludeCertificate:   true,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignCMS(attached) failed: %v", err)
	}
	attachedVerification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
		Signature:            Bytes(attached.Data),
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("VerifyCMS(attached) failed: %v", err)
	}
	requireContains(t, "attached CMS verification", attachedVerification.Info, "Verify - OK")
	if string(attachedVerification.Data) != string(payload) {
		t.Fatalf("attached CMS data = %q, want %q", attachedVerification.Data, payload)
	}

	detached, err := client.SignCMS(ctx, SignCMSRequest{
		Data:                 Bytes(payload),
		Detached:             true,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignCMS(detached) failed: %v", err)
	}
	detachedVerification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
		Signature:            Bytes(detached.Data),
		Data:                 Bytes(payload),
		Detached:             true,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("VerifyCMS(detached) failed: %v", err)
	}
	requireContains(t, "detached CMS verification", detachedVerification.Info, "Verify - OK")
}

func assertSDKXML(t *testing.T, ctx context.Context, client *Client, assets sdkAssets) {
	t.Helper()

	signedXML, err := client.SignXML(ctx, SignXMLRequest{
		XML:                  Bytes(readSDKExample(t, assets, "test_xml")),
		Canonicalization:     XMLCanonicalizationInclusive,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignXML failed: %v", err)
	}
	requireContains(t, "signed XML", string(signedXML.XML), "<ds:Signature")
	if xmlVerification, err := client.VerifyXML(ctx, VerifyXMLRequest{
		XML:                  Bytes(signedXML.XML),
		Canonicalization:     XMLCanonicalizationInclusive,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	}); err == nil {
		requireContains(t, "XML verification", xmlVerification.Info, "OK")
	} else {
		requireKalkanError(t, "VerifyXML", err)
	}
}

func assertSDKWSSE(t *testing.T, ctx context.Context, client *Client, assets sdkAssets) {
	t.Helper()

	signedWSSE, err := client.SignWSSE(ctx, SignWSSERequest{
		XML:                  Bytes(readSDKExample(t, assets, "test_wsse")),
		BodyID:               "TheBody",
		Canonicalization:     XMLCanonicalizationInclusive,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignWSSE failed: %v", err)
	}
	requireContains(t, "signed WSSE", string(signedWSSE.XML), "wsse:Security")
	requireContains(t, "signed WSSE", string(signedWSSE.XML), "ds:Signature")
}

func assertSDKCertificateValidation(t *testing.T, ctx context.Context, client *Client, assets sdkAssets) {
	t.Helper()

	rootCertPath := sdkCertificatePath(t, assets, "root_test_gost_2022")
	rootCert, err := os.ReadFile(rootCertPath)
	if err != nil {
		t.Fatalf("read root certificate: %v", err)
	}
	certValidation, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
		Certificate:          sdkCertificateSource(rootCert),
		Mode:                 CertificateValidationNone,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err == nil && !certValidation.Valid {
		t.Fatal("ValidateCertificate(root cert) returned invalid result")
	}
	if err != nil {
		requireKalkanError(t, "ValidateCertificate(root cert)", err)
	}

	rootDER := certificateDERForTest(t, rootCert)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	rootBase64 := []byte(base64.StdEncoding.EncodeToString(rootDER))

	for _, test := range []struct {
		name   string
		source Source
	}{
		{name: "DER", source: DER(rootDER)},
		{name: "PEM", source: PEM(rootPEM)},
		{name: "Base64", source: Base64(rootBase64)},
	} {
		t.Run("source encoding "+test.name, func(t *testing.T) {
			validation, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
				Certificate:          test.source,
				Mode:                 CertificateValidationNone,
				CertificateTimeCheck: SkipCertificateTimeCheck,
			})
			if err == nil && !validation.Valid {
				t.Fatalf("ValidateCertificate(%s) returned invalid result", test.name)
			}
			if err != nil {
				requireKalkanError(t, "ValidateCertificate("+test.name+")", err)
			}
		})
	}
}

func certificateDERForTest(t *testing.T, cert []byte) []byte {
	t.Helper()

	if block, _ := pem.Decode(cert); block != nil {
		return block.Bytes
	}

	return cert
}

func TestSDKZIPSignerCertificateExtractionErrorAllowList(t *testing.T) {
	for _, code := range []ckalkan.ErrorCode{
		ckalkan.ErrorOpenFile,
		ckalkan.ErrorXMLParse,
		ckalkan.ErrorCheck,
		ckalkan.ErrorFileRead,
		ckalkan.ErrorZipExtract,
	} {
		if !isAcceptableSDKZIPSignerCertificateExtractionError(&ckalkan.KalkanError{Code: code}) {
			t.Fatalf("code %s was rejected", code.Hex())
		}
	}

	for _, err := range []error{
		errors.New("plain error"),
		&ckalkan.KalkanError{Code: ckalkan.ErrorInvalidFlag},
	} {
		if isAcceptableSDKZIPSignerCertificateExtractionError(err) {
			t.Fatalf("error %v was accepted", err)
		}
	}
}

func isAcceptableSDKZIPSignerCertificateExtractionError(err error) bool {
	code, ok := ckalkan.ErrorCodeOf(err)
	if !ok {
		return false
	}

	// KalkanCrypt 2.0.13 can verify SDK ZIP fixtures successfully and still
	// fail the separate signer-certificate extraction call for the same file.
	// Keep this list narrow so real VerifyZIP failures still fail the test.
	switch code {
	case ckalkan.ErrorOpenFile,
		ckalkan.ErrorXMLParse,
		ckalkan.ErrorCheck,
		ckalkan.ErrorFileRead,
		ckalkan.ErrorZipExtract:
		return true
	default:
		return false
	}
}

func assertSDKZIP(t *testing.T, ctx context.Context, client *Client, assets sdkAssets, payload []byte) {
	t.Helper()

	zipInputPath := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(zipInputPath, payload, 0o644); err != nil {
		t.Fatalf("write ZIP payload: %v", err)
	}
	signedZIP, err := client.SignZIP(ctx, SignZIPRequest{
		InputPath:            zipInputPath,
		OutputPath:           filepath.Join(t.TempDir(), "signed-root-container.zip"),
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignZIP failed: %v", err)
	}
	if _, err := os.Stat(signedZIP.Path); err != nil {
		t.Fatalf("SignZIP returned missing output %s: %v", signedZIP.Path, err)
	}

	mixedCaseZIPPath := filepath.Join(t.TempDir(), "signed-root-container.ZIP")
	mixedCaseZIP, err := client.SignZIP(ctx, SignZIPRequest{
		InputPath:            zipInputPath,
		OutputPath:           mixedCaseZIPPath,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignZIP(mixed-case .ZIP) failed: %v", err)
	}
	mixedCaseNormalizedPath := filepath.Join(filepath.Dir(mixedCaseZIPPath), "signed-root-container.zip")
	if mixedCaseZIP.Path != mixedCaseNormalizedPath {
		t.Fatalf("SignZIP(mixed-case .ZIP) path = %q, want normalized %q", mixedCaseZIP.Path, mixedCaseNormalizedPath)
	}
	if _, err := os.Stat(mixedCaseZIP.Path); err != nil {
		t.Fatalf("SignZIP(mixed-case .ZIP) returned missing output %s: %v", mixedCaseZIP.Path, err)
	}

	_, err = client.SignZIP(ctx, SignZIPRequest{
		InputPath:            zipInputPath,
		OutputPath:           filepath.Join(t.TempDir(), "signed-root-container"),
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "ZIP output extension must be .zip") {
		t.Fatalf("SignZIP(no .zip) error = %v, want .zip extension rejection", err)
	}

	if len(assets.ZIPs) == 0 {
		t.Log("no SDK ZIP containers found; skipping VerifyZIP success path")
		return
	}

	zipPath, zipVerification := verifiedSDKZIPFixture(t, ctx, client, assets.ZIPs)
	requireContains(t, "ZIP verification", zipVerification.Info, "Checking zip - OK")
	requireContains(t, "ZIP verification", zipVerification.Info, "Verify - OK")

	zipCert, err := client.ZIPSignerCertificate(ctx, ZIPSignerCertificateRequest{
		Path:                 zipPath,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err == nil {
		_ = zipCert
	} else {
		// Some KalkanCrypt 2.0.13 builds verify SDK ZIP fixtures but reject
		// standalone certificate extraction for the same fixture.
		if !isAcceptableSDKZIPSignerCertificateExtractionError(err) {
			t.Fatalf("ZIPSignerCertificate(%s) failed: %v", zipPath, err)
		}
		t.Logf("ZIPSignerCertificate(%s) returned tolerated SDK fixture error: %v", filepath.Base(zipPath), err)
	}
}

func verifiedSDKZIPFixture(t *testing.T, ctx context.Context, client *Client, zipPaths []string) (string, *ZIPVerification) {
	t.Helper()

	var failures []string
	for _, zipPath := range zipPaths {
		zipVerification, err := client.VerifyZIP(ctx, VerifyZIPRequest{
			Path:                 zipPath,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", filepath.Base(zipPath), err))
			continue
		}
		if !zipVerification.Valid {
			failures = append(failures, filepath.Base(zipPath)+": VerifyZIP returned invalid result")
			continue
		}
		if !strings.Contains(zipVerification.Info, "Checking zip - OK") {
			failures = append(failures, fmt.Sprintf("%s: missing %q in info %q", filepath.Base(zipPath), "Checking zip - OK", zipVerification.Info))
			continue
		}
		if !strings.Contains(zipVerification.Info, "Verify - OK") {
			failures = append(failures, fmt.Sprintf("%s: missing %q in info %q", filepath.Base(zipPath), "Verify - OK", zipVerification.Info))
			continue
		}

		return zipPath, zipVerification
	}

	t.Fatalf("no SDK ZIP fixture could be verified:\n%s", strings.Join(failures, "\n"))
	return "", nil
}
