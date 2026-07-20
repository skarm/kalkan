package kalkan

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestCMSFixturesContainExpectedSigningTimes(t *testing.T) {
	tests := []struct {
		name      string
		wantTimes []time.Time
	}{
		{
			name: "test_CMS_GOST.txt",
			wantTimes: []time.Time{
				time.Date(2018, 12, 21, 9, 24, 0, 0, time.UTC),
				time.Date(2018, 12, 21, 9, 25, 4, 0, time.UTC),
			},
		},
		{
			name: "CMS_for_double_sign.txt",
			wantTimes: []time.Time{
				time.Date(2019, 8, 26, 6, 12, 23, 0, time.UTC),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "examples", test.name))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(data)
			if block == nil {
				t.Fatalf("%s is not PEM data", test.name)
			}

			gotTimes := collectASN1UTCTimes(block.Bytes)
			for _, want := range test.wantTimes {
				if !containsTime(gotTimes, want) {
					t.Fatalf("%s UTCTimes = %v, want %s", test.name, gotTimes, want)
				}
			}
		})
	}
}

func collectASN1UTCTimes(der []byte) []time.Time {
	var times []time.Time
	for len(der) != 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(der, &raw)
		if err != nil {
			return times
		}

		if raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagUTCTime {
			if parsed, ok := parseASN1UTCTime(raw.Bytes); ok {
				times = append(times, parsed)
			}
		}
		if raw.IsCompound {
			times = append(times, collectASN1UTCTimes(raw.Bytes)...)
		}

		der = rest
	}

	return times
}

func parseASN1UTCTime(value []byte) (time.Time, bool) {
	for _, layout := range []string{"060102150405Z0700", "060102150405Z"} {
		parsed, err := time.Parse(layout, string(value))
		if err == nil {
			return parsed.UTC(), true
		}
	}

	return time.Time{}, false
}

func containsTime(times []time.Time, want time.Time) bool {
	for _, got := range times {
		if got.Equal(want) {
			return true
		}
	}

	return false
}

func TestVerifyCMSFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)

	t.Run("attached timestamped CMS", func(t *testing.T) {
		cms := readFixtureExample(t, assets, "test_CMS_GOST")
		verification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
			Signature:            PEM(cms),
			CertificateTimeCheck: SkipCertificateTimeCheck,
		})
		if err != nil {
			t.Fatalf("VerifyCMS(test_CMS_GOST) failed: %v", err)
		}
		requireContains(t, "test_CMS_GOST verification", verification.Info, "Verify - OK")
		requireContains(t, "test_CMS_GOST verification", verification.Info, "CAdES-T")
		if len(verification.Data) == 0 {
			t.Fatal("VerifyCMS(test_CMS_GOST) returned empty attached data")
		}

		if _, err := client.GetTimeFromSig(ctx, PEM(cms)); err == nil {
			t.Fatal("GetTimeFromSig(test_CMS_GOST) unexpectedly succeeded for expired CMS fixture fixture")
		} else {
			requireKalkanError(t, "GetTimeFromSig(test_CMS_GOST)", err)
		}
	})

	t.Run("detached CMS without data", func(t *testing.T) {
		cms := readFixtureExample(t, assets, "CMS_for_double_sign")
		if _, err := client.GetTimeFromSig(ctx, PEM(cms)); !isKalkanErrorCode(err, ckalkan.ErrorNoTSAToken) {
			t.Fatalf("GetTimeFromSig(CMS_for_double_sign) error = %v, want ErrorNoTSAToken", err)
		}
		if _, err := client.VerifyCMS(ctx, VerifyCMSRequest{
			Signature:            PEM(cms),
			CertificateTimeCheck: SkipCertificateTimeCheck,
		}); err == nil {
			t.Fatal("VerifyCMS(CMS_for_double_sign without detached data) unexpectedly succeeded")
		} else {
			requireKalkanError(t, "VerifyCMS(CMS_for_double_sign without detached data)", err)
		}
	})
}

type documentCMSFixture struct {
	name string
}

var documentCMSFixtures = []documentCMSFixture{
	{name: "legal_entity"},
	{name: "individual"},
}

func TestDocumentCMSFixturesAreConsistent(t *testing.T) {
	for _, fixture := range documentCMSFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			document := readDocumentCMSFixture(t, fixture, "document.txt")

			detachedSignature := readDocumentCMSFixture(t, fixture, "detached.der")
			detachedContent, detachedCertificates, err := cmsContentAndCertificates(detachedSignature)
			if err != nil {
				t.Fatalf("parse detached CMS: %v", err)
			}
			if detachedContent != nil {
				t.Fatal("detached.der unexpectedly contains attached content")
			}

			attachedSignature := readDocumentCMSFixture(t, fixture, "attached.der")
			attachedContent, attachedCertificates, err := cmsContentAndCertificates(attachedSignature)
			if err != nil {
				t.Fatalf("parse attached CMS: %v", err)
			}
			if !bytes.Equal(attachedContent, document) {
				t.Fatal("attached.der content does not match document.txt")
			}

			certificate := decodeDocumentCMSCertificate(t, fixture)
			if !containsDERCertificate(detachedCertificates, certificate) || !containsDERCertificate(attachedCertificates, certificate) {
				t.Fatal("CMS signer certificate does not match signer.cer")
			}
		})
	}
}

func TestDocumentCMSFixtureSignerCertificates(t *testing.T) {
	for _, fixture := range documentCMSFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			certificate := decodeDocumentCMSCertificate(t, fixture)
			certificateID, err := parseCertificateIdentifier(certificate)
			if err != nil {
				t.Fatalf("parse signer.cer: %v", err)
			}

			for _, signatureName := range []string{"detached.der", "attached.der"} {
				t.Run(signatureName, func(t *testing.T) {
					signerID, err := cmsSignerIdentifier(readDocumentCMSFixture(t, fixture, signatureName))
					if err != nil {
						t.Fatalf("parse signer identifier: %v", err)
					}
					if !bytes.Equal(signerID.issuer, certificateID.issuer) {
						t.Fatal("CMS signer issuer does not match signer.cer issuer")
					}
					if signerID.serial.Cmp(certificateID.serial) != 0 {
						t.Fatalf("CMS signer serial = %X, want %X", signerID.serial, certificateID.serial)
					}
				})
			}
		})
	}
}

func TestVerifyDocumentCMSFixtures(t *testing.T) {
	ctx := context.Background()
	assets := loadFixtureAssets(t)
	client := openFixtureClient(t, assets)

	for _, fixture := range documentCMSFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			document := readDocumentCMSFixture(t, fixture, "document.txt")
			detachedSignature := readDocumentCMSFixture(t, fixture, "detached.der")
			attachedSignature := readDocumentCMSFixture(t, fixture, "attached.der")
			for _, input := range []struct {
				name        string
				signature   Source
				data        Source
				detached    bool
				wantPayload bool
			}{
				{
					name:      "detached DER",
					signature: DER(detachedSignature),
					data:      Bytes(document),
					detached:  true,
				},
				{
					name:      "detached Base64",
					signature: Base64([]byte(base64.StdEncoding.EncodeToString(detachedSignature))),
					data:      Bytes(document),
					detached:  true,
				},
				{
					name:        "attached DER",
					signature:   DER(attachedSignature),
					wantPayload: true,
				},
				{
					name:        "attached Base64",
					signature:   Base64([]byte(base64.StdEncoding.EncodeToString(attachedSignature))),
					wantPayload: true,
				},
			} {
				t.Run(input.name, func(t *testing.T) {
					// These fixtures exercise CMS encoding and attachment variants. Their
					// certificates are time-bounded test assets, so certificate-time policy
					// is covered separately by deterministic unit tests.
					verification, err := client.VerifyCMS(ctx, VerifyCMSRequest{
						Signature:            input.signature,
						Data:                 input.data,
						Detached:             input.detached,
						CertificateTimeCheck: SkipCertificateTimeCheck,
					})
					if err != nil {
						t.Fatalf("VerifyCMS failed: %v", err)
					}
					requireContains(t, "verification", verification.Info, "Verify - OK")
					if input.wantPayload && !bytes.Equal(verification.Data, document) {
						t.Fatalf("VerifyCMS data = %q, want attached document", verification.Data)
					}
				})
			}
		})
	}
}

func readDocumentCMSFixture(t *testing.T, fixture documentCMSFixture, name string) []byte {
	t.Helper()

	path := filepath.Join("testdata", "cms", fixture.name+"_"+name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return data
}

func decodeDocumentCMSCertificate(t *testing.T, fixture documentCMSFixture) []byte {
	t.Helper()

	data := readDocumentCMSFixture(t, fixture, "signer.cer")
	certificate, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("decode signer.cer: %v", err)
	}

	return certificate
}

func containsDERCertificate(certificates [][]byte, want []byte) bool {
	for _, certificate := range certificates {
		if bytes.Equal(certificate, want) {
			return true
		}
	}

	return false
}

type certificateIdentifier struct {
	issuer []byte
	serial *big.Int
}

func certificateIdentifierFromIssuerAndSerial(issuer asn1.RawValue, serial *big.Int) certificateIdentifier {
	return certificateIdentifier{
		issuer: append([]byte(nil), issuer.FullBytes...),
		serial: new(big.Int).Set(serial),
	}
}

func parseCertificateIdentifier(der []byte) (certificateIdentifier, error) {
	var certificate asn1.RawValue
	rest, err := asn1.Unmarshal(der, &certificate)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode Certificate: %w", err)
	}
	if len(rest) != 0 || certificate.Class != asn1.ClassUniversal || certificate.Tag != asn1.TagSequence {
		return certificateIdentifier{}, errors.New("Certificate is not a single sequence")
	}

	var tbsCertificate asn1.RawValue
	_, err = asn1.Unmarshal(certificate.Bytes, &tbsCertificate)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode TBSCertificate: %w", err)
	}
	if tbsCertificate.Class != asn1.ClassUniversal || tbsCertificate.Tag != asn1.TagSequence {
		return certificateIdentifier{}, errors.New("TBSCertificate is not a sequence")
	}

	fields := tbsCertificate.Bytes
	var first asn1.RawValue
	fields, err = asn1.Unmarshal(fields, &first)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode certificate version or serial: %w", err)
	}
	if first.Class != asn1.ClassContextSpecific || first.Tag != 0 {
		fields = tbsCertificate.Bytes
	}

	var serial *big.Int
	fields, err = asn1.Unmarshal(fields, &serial)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode certificate serial: %w", err)
	}
	if serial.Sign() < 0 {
		return certificateIdentifier{}, errors.New("certificate serial is negative")
	}

	var signatureAlgorithm asn1.RawValue
	fields, err = asn1.Unmarshal(fields, &signatureAlgorithm)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode certificate signature algorithm: %w", err)
	}
	var issuer asn1.RawValue
	_, err = asn1.Unmarshal(fields, &issuer)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode certificate issuer: %w", err)
	}
	if issuer.Class != asn1.ClassUniversal || issuer.Tag != asn1.TagSequence {
		return certificateIdentifier{}, errors.New("certificate issuer is not a sequence")
	}

	return certificateIdentifierFromIssuerAndSerial(issuer, serial), nil
}

func cmsContentAndCertificates(der []byte) ([]byte, [][]byte, error) {
	fields, err := cmsSignedDataFields(der)
	if err != nil {
		return nil, nil, err
	}

	return cmsContentAndCertificatesFromFields(fields)
}

func cmsContentAndCertificatesFromFields(fields []byte) ([]byte, [][]byte, error) {
	var err error

	var version int
	fields, err = asn1.Unmarshal(fields, &version)
	if err != nil {
		return nil, nil, fmt.Errorf("decode SignedData version: %w", err)
	}
	var digestAlgorithms asn1.RawValue
	fields, err = asn1.Unmarshal(fields, &digestAlgorithms)
	if err != nil {
		return nil, nil, fmt.Errorf("decode SignedData digest algorithms: %w", err)
	}
	var encapsulatedContentInfo asn1.RawValue
	fields, err = asn1.Unmarshal(fields, &encapsulatedContentInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("decode encapContentInfo: %w", err)
	}

	content, err := cmsEncapsulatedContent(encapsulatedContentInfo)
	if err != nil {
		return nil, nil, err
	}

	var certificates asn1.RawValue
	_, err = asn1.Unmarshal(fields, &certificates)
	if err != nil {
		return nil, nil, fmt.Errorf("decode certificate set: %w", err)
	}
	if certificates.Class != asn1.ClassContextSpecific || certificates.Tag != 0 {
		return nil, nil, fmt.Errorf("certificate set has class %d tag %d, want [0]", certificates.Class, certificates.Tag)
	}

	var certificateDERs [][]byte
	certificateSet := certificates.Bytes
	for len(certificateSet) != 0 {
		var certificate asn1.RawValue
		certificateSet, err = asn1.Unmarshal(certificateSet, &certificate)
		if err != nil {
			return nil, nil, fmt.Errorf("decode certificate set entry: %w", err)
		}
		certificateDERs = append(certificateDERs, certificate.FullBytes)
	}
	if len(certificateDERs) == 0 {
		return nil, nil, errors.New("certificate set is empty")
	}

	return content, certificateDERs, nil
}

func cmsSignerIdentifier(der []byte) (certificateIdentifier, error) {
	fields, err := cmsSignedDataFields(der)
	if err != nil {
		return certificateIdentifier{}, err
	}

	var version int
	fields, err = asn1.Unmarshal(fields, &version)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode SignedData version: %w", err)
	}
	var digestAlgorithms asn1.RawValue
	fields, err = asn1.Unmarshal(fields, &digestAlgorithms)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode SignedData digest algorithms: %w", err)
	}
	var encapsulatedContentInfo asn1.RawValue
	fields, err = asn1.Unmarshal(fields, &encapsulatedContentInfo)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode encapContentInfo: %w", err)
	}
	if _, err := cmsEncapsulatedContent(encapsulatedContentInfo); err != nil {
		return certificateIdentifier{}, err
	}

	var certificates asn1.RawValue
	fields, err = asn1.Unmarshal(fields, &certificates)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode certificate set: %w", err)
	}
	if certificates.Class != asn1.ClassContextSpecific || certificates.Tag != 0 {
		return certificateIdentifier{}, fmt.Errorf("certificate set has class %d tag %d, want [0]", certificates.Class, certificates.Tag)
	}

	var signerInfos asn1.RawValue
	_, err = asn1.Unmarshal(fields, &signerInfos)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode signerInfos: %w", err)
	}
	if signerInfos.Class != asn1.ClassUniversal || signerInfos.Tag != asn1.TagSet {
		return certificateIdentifier{}, errors.New("signerInfos is not a set")
	}

	var signerInfo asn1.RawValue
	rest, err := asn1.Unmarshal(signerInfos.Bytes, &signerInfo)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode SignerInfo: %w", err)
	}
	if len(rest) != 0 || signerInfo.Class != asn1.ClassUniversal || signerInfo.Tag != asn1.TagSequence {
		return certificateIdentifier{}, errors.New("expected exactly one SignerInfo sequence")
	}

	signerFields := signerInfo.Bytes
	var signerVersion int
	signerFields, err = asn1.Unmarshal(signerFields, &signerVersion)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode SignerInfo version: %w", err)
	}
	var signerIdentifier asn1.RawValue
	_, err = asn1.Unmarshal(signerFields, &signerIdentifier)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode SignerIdentifier: %w", err)
	}
	if signerIdentifier.Class != asn1.ClassUniversal || signerIdentifier.Tag != asn1.TagSequence {
		return certificateIdentifier{}, errors.New("SignerIdentifier is not issuerAndSerialNumber")
	}

	identifierFields := signerIdentifier.Bytes
	var issuer asn1.RawValue
	identifierFields, err = asn1.Unmarshal(identifierFields, &issuer)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode signer issuer: %w", err)
	}
	var serial *big.Int
	identifierFields, err = asn1.Unmarshal(identifierFields, &serial)
	if err != nil {
		return certificateIdentifier{}, fmt.Errorf("decode signer serial: %w", err)
	}
	if len(identifierFields) != 0 {
		return certificateIdentifier{}, errors.New("SignerIdentifier has trailing bytes")
	}

	return certificateIdentifierFromIssuerAndSerial(issuer, serial), nil
}

func cmsSignedDataFields(der []byte) ([]byte, error) {
	var contentInfo asn1.RawValue
	rest, err := asn1.Unmarshal(der, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("decode ContentInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("decode ContentInfo: trailing bytes")
	}
	if contentInfo.Class != asn1.ClassUniversal || contentInfo.Tag != asn1.TagSequence {
		return nil, errors.New("ContentInfo is not a sequence")
	}

	rest = contentInfo.Bytes
	var contentType asn1.ObjectIdentifier
	rest, err = asn1.Unmarshal(rest, &contentType)
	if err != nil {
		return nil, fmt.Errorf("decode ContentInfo type: %w", err)
	}
	if !contentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return nil, fmt.Errorf("ContentInfo type = %s, want signedData", contentType)
	}

	var signedDataWrapper asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &signedDataWrapper)
	if err != nil {
		return nil, fmt.Errorf("decode SignedData wrapper: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("decode SignedData wrapper: trailing bytes")
	}
	if signedDataWrapper.Class != asn1.ClassContextSpecific || signedDataWrapper.Tag != 0 {
		return nil, fmt.Errorf("SignedData wrapper has class %d tag %d, want [0]", signedDataWrapper.Class, signedDataWrapper.Tag)
	}

	var signedData asn1.RawValue
	rest, err = asn1.Unmarshal(signedDataWrapper.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("decode SignedData: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("decode SignedData: trailing bytes")
	}
	if signedData.Class != asn1.ClassUniversal || signedData.Tag != asn1.TagSequence {
		return nil, errors.New("SignedData is not a sequence")
	}

	return signedData.Bytes, nil
}

func cmsEncapsulatedContent(raw asn1.RawValue) ([]byte, error) {
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
		return nil, errors.New("encapContentInfo is not a sequence")
	}

	rest := raw.Bytes
	var contentType asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(rest, &contentType)
	if err != nil {
		return nil, fmt.Errorf("decode encapsulated content type: %w", err)
	}
	if !contentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}) {
		return nil, fmt.Errorf("encapsulated content type = %s, want data", contentType)
	}
	if len(rest) == 0 {
		return nil, nil
	}

	var contentWrapper asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &contentWrapper)
	if err != nil {
		return nil, fmt.Errorf("decode encapsulated content wrapper: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("decode encapsulated content wrapper: trailing bytes")
	}
	if contentWrapper.Class != asn1.ClassContextSpecific || contentWrapper.Tag != 0 {
		return nil, fmt.Errorf("encapsulated content wrapper has class %d tag %d, want [0]", contentWrapper.Class, contentWrapper.Tag)
	}

	var content []byte
	rest, err = asn1.Unmarshal(contentWrapper.Bytes, &content)
	if err != nil {
		return nil, fmt.Errorf("decode encapsulated content: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("decode encapsulated content: trailing bytes")
	}

	return content, nil
}
