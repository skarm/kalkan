package kalkan

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
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
				Path:                 copyZIPFixture(t, zipPath),
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
		Path:                 copyZIPFixture(t, zipPath),
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("VerifyZIP(%s) failed: %v", zipPath, err)
	}
	requireContains(t, "ZIP verification", verification.Info, "Checking zip - OK")
	requireContains(t, "ZIP verification", verification.Info, "Verify - OK")
}
