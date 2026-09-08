package kalkan

import (
	"bytes"
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

	"github.com/skarm/kalkan/internal/testfixture"
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
			detachedContent, detachedCertificates, err := testfixture.CMSContentAndCertificates(detachedSignature)
			if err != nil {
				t.Fatalf("parse detached CMS: %v", err)
			}
			if detachedContent != nil {
				t.Fatal("detached.der unexpectedly contains attached content")
			}

			attachedSignature := readDocumentCMSFixture(t, fixture, "attached.der")
			attachedContent, attachedCertificates, err := testfixture.CMSContentAndCertificates(attachedSignature)
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

func cmsSignerIdentifier(der []byte) (certificateIdentifier, error) {
	fields, err := testfixture.CMSSignedDataFields(der)
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
	if _, err := testfixture.CMSEncapsulatedContent(encapsulatedContentInfo); err != nil {
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
