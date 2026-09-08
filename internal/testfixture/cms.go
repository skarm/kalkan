package testfixture

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"
)

// CMSContentAndCertificates decodes the content and certificates of a signed CMS fixture.
func CMSContentAndCertificates(der []byte) ([]byte, [][]byte, error) {
	fields, err := CMSSignedDataFields(der)
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

	content, err := CMSEncapsulatedContent(encapsulatedContentInfo)
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

// CMSSignedDataFields returns the ASN.1 fields of a CMS SignedData sequence.
func CMSSignedDataFields(der []byte) ([]byte, error) {
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

// CMSEncapsulatedContent reads a CMS content wrapper, preserving absent detached content.
func CMSEncapsulatedContent(raw asn1.RawValue) ([]byte, error) {
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

// CMSEnvelope represents CMS ContentInfo wrapping SignedData.
type CMSEnvelope struct {
	ContentType asn1.ObjectIdentifier
	Content     CMSSignedData `asn1:"explicit,tag:0"`
}

// CMSSignedData is the independent fixture model of CMS SignedData.
type CMSSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []CMSSignerInfo `asn1:"set"`
}

// CMSSignerInfo models a signer and its signed and unsigned attributes.
type CMSSignerInfo struct {
	Version            int
	Identifier         asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   []CMSAttribute `asn1:"optional,tag:0,set"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes []CMSAttribute `asn1:"optional,tag:1,set"`
}

// CMSAttribute models a CMS attribute and its ASN.1 value set.
type CMSAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// AssertSignHashCMSStructure checks the SDK GOST 512 SignHash CMS structure independently of the provider.
func AssertSignHashCMSStructure(t testing.TB, der, digest []byte) {
	t.Helper()

	var envelope CMSEnvelope
	if rest, err := asn1.Unmarshal(der, &envelope); err != nil || len(rest) != 0 {
		t.Fatalf("decode SignHash CMS: error=%v, trailing bytes=%d", err, len(rest))
	}

	if !envelope.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		t.Fatalf("SignHash ContentInfo type = %s, want signedData", envelope.ContentType)
	}

	content, certificates, err := CMSContentAndCertificates(der)
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
