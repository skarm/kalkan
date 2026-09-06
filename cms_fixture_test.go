package kalkan

import (
	"bytes"
	"crypto/x509/pkix"
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

type signHashCMSEnvelope struct {
	ContentType asn1.ObjectIdentifier
	Content     signHashCMSSignedData `asn1:"explicit,tag:0"`
}

type signHashCMSSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue           `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue           `asn1:"optional,tag:1"`
	SignerInfos      []signHashCMSSignerInfo `asn1:"set"`
}

type signHashCMSSignerInfo struct {
	Version            int
	Identifier         asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   []signHashCMSAttribute `asn1:"optional,tag:0,set"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes []signHashCMSAttribute `asn1:"optional,tag:1,set"`
}

type signHashCMSAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

func assertSignHashCMSStructure(t *testing.T, der, digest []byte) {
	t.Helper()

	var envelope signHashCMSEnvelope
	if rest, err := asn1.Unmarshal(der, &envelope); err != nil || len(rest) != 0 {
		t.Fatalf("decode SignHash CMS: error=%v, trailing bytes=%d", err, len(rest))
	}
	if !envelope.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		t.Fatalf("SignHash ContentInfo type = %s, want signedData", envelope.ContentType)
	}
	content, certificates, err := cmsContentAndCertificates(der)
	if err != nil || content != nil || len(certificates) == 0 {
		t.Fatalf("SignHash CMS: content=%x, certificates=%d, error=%v; want detached CMS with signer certificate", content, len(certificates), err)
	}

	// SDK 2.0.13's OBJ_id_GostR3411_2015_512 is OBJ_pkigovkz,3,3.
	// The bundled fixture key selects this Kazakhstan GOST 512-bit digest OID.
	wantDigestOID := asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 3, 3}
	algorithms := envelope.Content.DigestAlgorithms
	if len(algorithms) != 1 || !algorithms[0].Algorithm.Equal(wantDigestOID) {
		t.Fatalf("SignHash SignedData digest algorithms = %v, want only %s", algorithms, wantDigestOID)
	}
	if len(envelope.Content.SignerInfos) != 1 {
		t.Fatalf("SignHash signer count = %d, want 1", len(envelope.Content.SignerInfos))
	}
	signer := envelope.Content.SignerInfos[0]
	if !signer.DigestAlgorithm.Algorithm.Equal(wantDigestOID) {
		t.Fatalf("SignHash SignerInfo digest algorithm = %s, want %s", signer.DigestAlgorithm.Algorithm, wantDigestOID)
	}
	if len(signer.Signature) == 0 {
		t.Fatal("SignHash SignerInfo contains an empty signature")
	}

	messageDigestCount := 0
	for _, attribute := range signer.SignedAttributes {
		if !attribute.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}) {
			continue
		}
		messageDigestCount++
		if len(attribute.Values) != 1 {
			t.Fatalf("SignHash messageDigest value count = %d, want 1", len(attribute.Values))
		}
		var embeddedDigest []byte
		if rest, err := asn1.Unmarshal(attribute.Values[0].FullBytes, &embeddedDigest); err != nil || len(rest) != 0 {
			t.Fatalf("decode SignHash messageDigest: error=%v, trailing bytes=%d", err, len(rest))
		}
		if !bytes.Equal(embeddedDigest, digest) {
			t.Fatalf("SignHash messageDigest = %x, want supplied digest %x", embeddedDigest, digest)
		}
	}
	if messageDigestCount != 1 {
		t.Fatalf("SignHash messageDigest attribute count = %d, want 1", messageDigestCount)
	}
}
