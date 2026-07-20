package kalkan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientFixtureOperations(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)

	if err := client.LoadKeyStore(ctx, KeyStore{
		Type:     PKCS12,
		Path:     keyStorePath(t, assets),
		Password: fixturePassword,
	}); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}

	payload := []byte("root kalkan API fixture payload")

	t.Run("Hash", func(t *testing.T) {
		assertHashing(t, ctx, client, payload)
	})

	t.Run("SignHash", func(t *testing.T) {
		assertHashSigning(t, ctx, client, payload)
	})

	t.Run("CMS", func(t *testing.T) {
		assertCMS(t, ctx, client, payload)
	})

	t.Run("XML", func(t *testing.T) {
		assertXML(t, ctx, client, assets)
	})

	t.Run("WSSE", func(t *testing.T) {
		assertWSSE(t, ctx, client, assets)
	})

	t.Run("CertificateValidation", func(t *testing.T) {
		assertCertificateValidation(t, ctx, client, assets)
	})

	t.Run("CertificateInfo", func(t *testing.T) {
		assertCertificateInfo(t, ctx, client, assets)
	})

	t.Run("ZIP", func(t *testing.T) {
		assertZIP(t, ctx, client, payload)
	})
}

func TestClientFixtureLargeFileCMSRoundTrip(t *testing.T) {
	const payloadSize = 8 << 20

	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)
	if err := client.LoadKeyStore(ctx, KeyStore{
		Type:     PKCS12,
		Path:     keyStorePath(t, assets),
		Password: fixturePassword,
	}); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}

	payloadPath, payloadHash := writeLargeCMSPayloadFile(t, payloadSize)

	t.Run("attached", func(t *testing.T) {
		attached, err := client.SignCMS(ctx, SignCMSRequest{
			Data:                 File(payloadPath),
			IncludeCertificate:   true,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("SignCMS(attached file) failed: %v", err)
		}
		if len(attached.Data) <= payloadSize {
			t.Fatalf("attached CMS length = %d, want more than embedded payload size %d", len(attached.Data), payloadSize)
		}

		verification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
			Signature:            DER(attached.Data),
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("VerifyCMS(attached file) failed: %v", err)
		}
		requireContains(t, "attached CMS verification", verification.Info, "Verify - OK")
		if len(verification.Data) != payloadSize {
			t.Fatalf("attached CMS data length = %d, want %d", len(verification.Data), payloadSize)
		}
		if got := sha256.Sum256(verification.Data); got != payloadHash {
			t.Fatal("attached CMS data hash does not match the signed file")
		}
	})

	t.Run("detached", func(t *testing.T) {
		detached, err := client.SignCMS(ctx, SignCMSRequest{
			Data:                 File(payloadPath),
			Detached:             true,
			IncludeCertificate:   true,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("SignCMS(detached file) failed: %v", err)
		}
		if len(detached.Data) == 0 {
			t.Fatal("SignCMS(detached file) returned an empty CMS")
		}

		signaturePath := filepath.Join(t.TempDir(), "detached.cms")
		if err := os.WriteFile(signaturePath, detached.Data, 0o600); err != nil {
			t.Fatalf("write detached CMS: %v", err)
		}
		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("read detached CMS payload: %v", err)
		}
		if len(payload) != payloadSize || sha256.Sum256(payload) != payloadHash {
			t.Fatal("detached CMS payload does not match the file that was signed")
		}
		verification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
			Signature:            File(signaturePath),
			Data:                 Bytes(payload),
			Detached:             true,
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("VerifyCMS(detached file) failed: %v", err)
		}
		requireContains(t, "detached CMS verification", verification.Info, "Verify - OK")
	})
}

func writeLargeCMSPayloadFile(t *testing.T, size int) (string, [sha256.Size]byte) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "payload.bin")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create large CMS payload: %v", err)
	}

	block := make([]byte, 64<<10)
	for i := range block {
		block[i] = byte(i*31 + 17)
	}

	hash := sha256.New()
	for remaining := size; remaining > 0; {
		chunk := block[:min(len(block), remaining)]
		if _, err := file.Write(chunk); err != nil {
			_ = file.Close()
			t.Fatalf("write large CMS payload: %v", err)
		}
		if _, err := hash.Write(chunk); err != nil {
			_ = file.Close()
			t.Fatalf("hash large CMS payload: %v", err)
		}
		remaining -= len(chunk)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close large CMS payload: %v", err)
	}

	var sum [sha256.Size]byte
	copy(sum[:], hash.Sum(nil))

	return path, sum
}

func assertHashing(t *testing.T, ctx context.Context, client *Client, payload []byte) {
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

func assertHashSigning(t *testing.T, ctx context.Context, client *Client, payload []byte) {
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

func assertCMS(t *testing.T, ctx context.Context, client *Client, payload []byte) {
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

func assertXML(t *testing.T, ctx context.Context, client *Client, assets fixtureAssets) {
	t.Helper()

	signedXML, err := client.SignXML(ctx, SignXMLRequest{
		XML:                  Bytes(readFixtureExample(t, assets, "test_xml")),
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

func assertWSSE(t *testing.T, ctx context.Context, client *Client, assets fixtureAssets) {
	t.Helper()

	signedWSSE, err := client.SignWSSE(ctx, SignWSSERequest{
		XML:                  Bytes(readFixtureExample(t, assets, "test_wsse")),
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

func assertCertificateValidation(t *testing.T, ctx context.Context, client *Client, assets fixtureAssets) {
	t.Helper()

	rootCertPath := certificatePath(t, assets, "root_test_gost_2022")
	rootCert, err := os.ReadFile(rootCertPath)
	if err != nil {
		t.Fatalf("read root certificate: %v", err)
	}
	certValidation, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{
		Certificate:          certificateSource(rootCert),
		Mode:                 CertificateValidationNone,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err == nil && certValidation == nil {
		t.Fatal("ValidateCertificate(root cert) returned a nil result")
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
			if err == nil && validation == nil {
				t.Fatalf("ValidateCertificate(%s) returned a nil result", test.name)
			}
			if err != nil {
				requireKalkanError(t, "ValidateCertificate("+test.name+")", err)
			}
		})
	}
}

func assertCertificateInfo(t *testing.T, ctx context.Context, client *Client, assets fixtureAssets) {
	t.Helper()

	certData := readFixtureExample(t, assets, "test_CERT_GOST")
	cert, err := parseNativeCertificate(certData)
	if err != nil {
		t.Fatalf("parse fixture certificate fixture: %v", err)
	}

	info, err := client.X509CertificateGetInfoFields(
		ctx,
		cert,
		CertificateInfoSubjectCountry|
			CertificateInfoSubjectSerialNumber|
			CertificateInfoSubjectOrganization|
			CertificateInfoSubjectOrganizationalUnit|
			CertificateInfoPolicy,
	)
	if err != nil {
		t.Fatalf("X509CertificateGetInfoFields(test_CERT_GOST) failed: %v", err)
	}

	if info.SubjectCountry != "KZ" {
		t.Fatalf("SubjectCountry = %q, want KZ", info.SubjectCountry)
	}
	if info.IIN != "123456789012" {
		t.Fatalf("IIN = %q, want 123456789012", info.IIN)
	}
	if info.BIN != "123456789021" {
		t.Fatalf("BIN = %q, want 123456789021", info.BIN)
	}
	if info.SubjectType != CertificateSubjectLegalEntity {
		t.Fatalf("SubjectType = %q, want legal entity fallback from BIN", info.SubjectType)
	}
	if len(info.Roles) != 0 {
		t.Fatalf("Roles = %#v, want none for test_CERT_GOST policy %q", info.Roles, info.Policy)
	}
}

func certificateDERForTest(t *testing.T, cert []byte) []byte {
	t.Helper()

	if block, _ := pem.Decode(cert); block != nil {
		return block.Bytes
	}

	return cert
}

func assertZIP(t *testing.T, ctx context.Context, client *Client, payload []byte) {
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
}
