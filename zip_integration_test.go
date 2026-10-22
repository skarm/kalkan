package kalkan

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/internal/testfixture"
)

func TestZIPFixturesMatchManifestAndExpectedPayloads(t *testing.T) {
	tests := []struct {
		name     string
		payloads []string
	}{
		{
			name:     "sign.zip",
			payloads: []string{"double_sign.txt", "outToFile.der", "test_pdf.pdf", "text _hash.docx", "xml.xml"},
		},
		{
			name:     "zip_multiply.zip",
			payloads: []string{"double_sign.txt", "outToFile.der", "test_pdf.pdf", "text _hash.docx", "xml.xml"},
		},
		{
			name:     "zip_signed_files.zip",
			payloads: []string{"CMS_for_double_sign.txt", "application.pdf", "signPDF_in_base64", "wsse.txt"},
		},
		{
			name:     "zip_signed_folder.zip",
			payloads: []string{"CMS_for_double_sign.txt", "application.pdf", "signPDF_in_base64", "wsse.txt"},
		},
		{
			name:     "zip_with_ts.zip",
			payloads: []string{"wsse.txt"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archivePath := filepath.Join("testdata", "zip", test.name)
			reader, err := zip.OpenReader(archivePath)
			if err != nil {
				t.Fatalf("open %s: %v", archivePath, err)
			}
			defer reader.Close()

			entries := make(map[string]*zip.File)
			var payloads []string
			var signatures []string
			for _, file := range reader.File {
				if !safeZIPEntryName(file.Name) {
					t.Fatalf("unsafe ZIP entry %q", file.Name)
				}
				if entries[file.Name] != nil {
					t.Fatalf("duplicate ZIP entry %q", file.Name)
				}
				entries[file.Name] = file

				switch {
				case file.Name == "META-INF/NCAManifest.xml":
				case strings.HasPrefix(file.Name, "META-INF/") && strings.HasSuffix(file.Name, ".cms"):
					signatures = append(signatures, file.Name)
				default:
					payloads = append(payloads, file.Name)
				}
			}
			sort.Strings(payloads)
			sort.Strings(signatures)

			wantPayloads := sortedStrings(test.payloads)
			if !slices.Equal(payloads, wantPayloads) {
				t.Fatalf("payload entries = %#v, want %#v", payloads, wantPayloads)
			}
			if len(signatures) != 1 {
				t.Fatalf("signature entries = %#v, want exactly one CMS signature", signatures)
			}
			if entries["META-INF/NCAManifest.xml"] == nil {
				t.Fatal("missing META-INF/NCAManifest.xml")
			}

			manifest := readNCAManifest(t, entries["META-INF/NCAManifest.xml"])
			if len(manifest.SigReferences) != 1 {
				t.Fatalf("manifest signature references = %#v, want one", manifest.SigReferences)
			}
			if manifest.SigReferences[0].URI != signatures[0] {
				t.Fatalf("manifest signature URI = %q, want %q", manifest.SigReferences[0].URI, signatures[0])
			}

			manifestPayloads := make([]string, 0, len(manifest.DataObjectReferences))

			for _, ref := range manifest.DataObjectReferences {
				if entries[ref.URI] == nil {
					t.Fatalf("manifest references missing payload %q", ref.URI)
				}
				if ref.DigestMethod.Algorithm != "http://www.w3.org/2001/04/xmldsig-more#gost34311" {
					t.Fatalf("digest algorithm for %s = %q", ref.URI, ref.DigestMethod.Algorithm)
				}
				digest, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ref.DigestValue))
				if err != nil {
					t.Fatalf("digest for %s is not base64: %v", ref.URI, err)
				}
				if len(digest) != 32 {
					t.Fatalf("digest for %s is %d bytes, want 32", ref.URI, len(digest))
				}
				manifestPayloads = append(manifestPayloads, ref.URI)
			}
			sort.Strings(manifestPayloads)
			if !slices.Equal(manifestPayloads, wantPayloads) {
				t.Fatalf("manifest payloads = %#v, want %#v", manifestPayloads, wantPayloads)
			}
		})
	}
}

func TestZIPFolderAndFileFixturesHaveSamePayloadSet(t *testing.T) {
	filesPayloads := zipPayloadEntries(t, filepath.Join("testdata", "zip", "zip_signed_files.zip"))
	folderPayloads := zipPayloadEntries(t, filepath.Join("testdata", "zip", "zip_signed_folder.zip"))

	if !slices.Equal(filesPayloads, folderPayloads) {
		t.Fatalf("zip_signed_files payloads = %#v, zip_signed_folder payloads = %#v", filesPayloads, folderPayloads)
	}
}

type ncaManifest struct {
	SigReferences        []ncaManifestReference `xml:"SigReference"`
	DataObjectReferences []ncaManifestReference `xml:"DataObjectReference"`
}

type ncaManifestReference struct {
	URI          string `xml:"URI,attr"`
	DigestMethod struct {
		Algorithm string `xml:"Algorithm,attr"`
	} `xml:"DigestMethod"`
	DigestValue string `xml:"DigestValue"`
}

func readNCAManifest(t *testing.T, file *zip.File) ncaManifest {
	t.Helper()

	reader, err := file.Open()
	if err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	defer reader.Close()

	var manifest ncaManifest
	if err := xml.NewDecoder(reader).Decode(&manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return manifest
}

func zipPayloadEntries(t *testing.T, archivePath string) []string {
	t.Helper()

	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatalf("open %s: %v", archivePath, err)
	}
	defer reader.Close()

	var payloads []string
	for _, file := range reader.File {
		if file.Name == "META-INF/NCAManifest.xml" {
			continue
		}
		if strings.HasPrefix(file.Name, "META-INF/") && strings.HasSuffix(file.Name, ".cms") {
			continue
		}
		payloads = append(payloads, file.Name)
	}
	sort.Strings(payloads)
	return payloads
}

func safeZIPEntryName(name string) bool {
	clean := path.Clean(name)
	return name != "" &&
		clean != "." &&
		!path.IsAbs(name) &&
		!strings.HasPrefix(clean, "../") &&
		clean != ".."
}

func sortedStrings(values []string) []string {
	sorted := slices.Clone(values)
	sort.Strings(sorted)
	return sorted
}

func TestVerifyZIPFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)
	if len(assets.ZIPs) == 0 {
		t.Skip("no ZIP fixture containers found")
	}

	for _, zipPath := range assets.ZIPs {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			verifyZIPFixture(t, ctx, client, zipPath)
		})
	}
}

func TestExtractZIPSignerCertificateFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)
	if len(assets.ZIPs) == 0 {
		t.Skip("no ZIP fixture containers found")
	}

	for _, zipPath := range assets.ZIPs {
		t.Run(filepath.Base(zipPath), func(t *testing.T) {
			cert, err := client.ExtractZIPSignerCertificate(ctx, ExtractZIPSignerCertificateRequest{
				Path:                 testfixture.CopyZIP(t, zipPath),
				CertificateTimeCheck: SkipCertificateTimeCheck,
			})
			if err != nil {
				if errors.Is(err, ErrInvalidInput) && strings.Contains(err.Error(), "ZIP signer certificate output is empty") {
					return
				}

				t.Fatalf("ExtractZIPSignerCertificate(%s) failed: %v", zipPath, err)
			}
			if isEmptyNativeCertificate(cert) {
				t.Fatal("ExtractZIPSignerCertificate returned an empty certificate without an error")
			}
		})
	}
}

func verifyZIPFixture(t *testing.T, ctx context.Context, client *Client, zipPath string) {
	t.Helper()

	verification, err := client.VerifyZIP(ctx, VerifyZIPRequest{
		Path:                 testfixture.CopyZIP(t, zipPath),
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("VerifyZIP(%s) failed: %v", zipPath, err)
	}
	requireContains(t, "ZIP verification", verification.Info, "Checking zip - OK")
	requireContains(t, "ZIP verification", verification.Info, "Verify - OK")
}

func TestSignZIPRejectsNonDirectoryNativeInput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("directory input guard applies to the Linux native adapter")
	}
	for _, atomic := range []bool{false, true} {
		t.Run(fmt.Sprintf("atomic_%v", atomic), func(t *testing.T) {
			var options []Option
			if atomic {
				options = append(options, WithAtomicZIPOutput())
			}
			client := openFixtureSigningClient(t, options...)
			inputDir, outDir := t.TempDir(), t.TempDir()
			payload := []byte("single input file must not silently disappear from the ZIP")
			file := filepath.Join(inputDir, "payload.txt")
			if err := os.WriteFile(file, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(t.TempDir(), "payload-link.txt")
			if err := os.Symlink(file, link); err != nil {
				t.Fatal(err)
			}
			for _, input := range []string{file, link, filepath.Join(inputDir, "missing")} {
				t.Run(filepath.Base(input), func(t *testing.T) {
					output := filepath.Join(outDir, "rejected.zip")
					result, err := client.SignZIP(t.Context(), SignZIPRequest{InputPath: input, OutputPath: output, CertificateTimeCheck: SkipCertificateTimeCheck})
					requireNativeErrorCode(t, "SignZIP(non-directory)", err, ckalkan.ErrorParam)
					if result != nil {
						t.Fatalf("invalid ZIP input returned success: %+v", result)
					}
					entries, err := os.ReadDir(outDir)
					if err != nil || len(entries) != 0 {
						t.Fatalf("failed signing left output/staging files: %v, %v", entries, err)
					}
				})
			}
			// The same payload, passed through its containing directory, must
			// still be included and cryptographically verified after rejections.
			signed, err := client.SignZIP(t.Context(), SignZIPRequest{InputPath: inputDir, OutputPath: filepath.Join(outDir, "valid.zip"), CertificateTimeCheck: SkipCertificateTimeCheck})
			if err != nil {
				t.Fatal(err)
			}
			archive, err := zip.OpenReader(signed.Path)
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			found := false
			for _, entry := range archive.File {
				if entry.Name != "payload.txt" {
					continue
				}
				reader, err := entry.Open()
				if err != nil {
					t.Fatal(err)
				}
				data, readErr := io.ReadAll(reader)
				closeErr := reader.Close()
				if readErr != nil || closeErr != nil || !bytes.Equal(data, payload) {
					t.Fatalf("ZIP payload = %q, read=%v close=%v", data, readErr, closeErr)
				}
				found = true
			}
			if !found {
				t.Fatal("signed ZIP is missing the original payload")
			}
			verification, err := client.VerifyZIP(t.Context(), VerifyZIPRequest{Path: signed.Path, CertificateTimeCheck: SkipCertificateTimeCheck})
			if err != nil || verification == nil || !strings.Contains(verification.Info, "Verify - OK") {
				t.Fatalf("directory signing positive control = %+v, %v", verification, err)
			}
		})
	}
}

func TestZIPVerificationRejectsChangedEntries(t *testing.T) {
	ctx := context.Background()
	client := openFixtureSigningClient(t)
	dir := t.TempDir()
	inputDir := filepath.Join(dir, "input")
	if err := os.Mkdir(inputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("ZIP verification authenticates this original-value\x00\xff")
	inputPath := filepath.Join(inputDir, "payload.bin")
	if err := os.WriteFile(inputPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	// The Linux SDK traverses a directory.
	// A regular-file input produces an empty manifest.
	// Use a directory for the positive control.
	signed, err := client.SignZIP(ctx, SignZIPRequest{InputPath: inputDir, OutputPath: filepath.Join(dir, "signed.zip"), CertificateTimeCheck: SkipCertificateTimeCheck})
	if err != nil {
		t.Fatal(err)
	}
	verify := func(path string) (*Verification, error) {
		return client.VerifyZIP(ctx, VerifyZIPRequest{Path: path, CertificateTimeCheck: SkipCertificateTimeCheck})
	}
	if control, err := verify(signed.Path); err != nil || control == nil || !strings.Contains(control.Info, "Checking zip - OK") || !strings.Contains(control.Info, "Verify - OK") {
		t.Fatalf("positive ZIP control = %+v, %v", control, err)
	}
	for _, mutation := range []string{"payload", "manifest", "signature"} {
		t.Run(mutation, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "changed.zip")
			rewriteSignedZIP(t, signed.Path, p, mutation)
			result, err := verify(p)
			want := ckalkan.ErrorVerify
			if mutation == "payload" {
				want = ckalkan.ErrorHash
			}
			requireNativeErrorCode(t, "VerifyZIP(changed "+mutation+")", err, want)
			if result != nil {
				t.Fatalf("changed %s returned successful verification: %+v", mutation, result)
			}
			code, _ := ckalkan.ErrorCodeOf(err)
			t.Logf("native rejection: %s: %v", code.Hex(), err)
		})
	}
	if _, err := verify(signed.Path); err != nil {
		t.Fatalf("valid ZIP after rejections: %v", err)
	}
}

func rewriteSignedZIP(t *testing.T, inputPath, outputPath, mutation string) {
	t.Helper()
	reader, err := zip.OpenReader(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	writer := zip.NewWriter(output)
	changed := false
	for _, entry := range reader.File {
		r, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(r)
		closeErr := r.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read ZIP entry %s: %v, %v", entry.Name, readErr, closeErr)
		}
		switch {
		case mutation == "payload" && entry.Name == "payload.bin":
			data[0] ^= 1
			changed = true
		case mutation == "manifest" && entry.Name == "META-INF/NCAManifest.xml":
			modified := bytes.Replace(data, []byte("\t<SigReference"), []byte("  <SigReference"), 1)
			changed = !bytes.Equal(modified, data)
			data = modified
		case mutation == "signature" && strings.HasSuffix(entry.Name, ".cms"):
			// The final octet belongs to the signature value in the SDK's
			// generated CMS. ASN.1 tags and lengths remain unchanged.
			data[len(data)-1] ^= 1
			changed = true
		}
		header := entry.FileHeader
		w, err := writer.CreateHeader(&header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatalf("ZIP %s mutation did not find its target", mutation)
	}
}
