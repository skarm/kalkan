package javakalkan_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/internal/testfixture"
)

// Fixtures use Go crypto to generate independent RSA certificates, CMS, and PKI
// responses. Java only packages generated signing keys as the SDK's PKCS12 format.
//
//go:embed testdata/CreateStore.java
var keyStoreSource []byte

func javaValidationKeyStore(t *testing.T, identity javaValidationIdentity) string {
	t.Helper()
	provider := os.Getenv("KALKANCRYPT_JAVA_PROVIDER")
	executable := os.Getenv("KALKANCRYPT_JAVA_EXECUTABLE")
	if executable == "" {
		executable = "java"
	}
	directory := t.TempDir()
	privateKey, err := x509.MarshalPKCS8PrivateKey(identity.key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	for name, data := range map[string][]byte{
		"key.der": privateKey, "certificate.der": identity.cert.Raw,
		"CreateStore.java": keyStoreSource,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(directory, "test.p12")
	command := exec.CommandContext(t.Context(), executable, "-cp", provider, filepath.Join(directory, "CreateStore.java"),
		filepath.Join(directory, "key.der"), filepath.Join(directory, "certificate.der"), output)
	if diagnostic, err := command.CombinedOutput(); err != nil {
		t.Fatalf("package generated PKCS12: %v\n%s", err, diagnostic)
	}
	return output
}

type javaTestTimestampImprint struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type javaTestTimestampRequest struct {
	Version    int
	Imprint    javaTestTimestampImprint
	Policy     asn1.ObjectIdentifier `asn1:"optional"`
	Nonce      *big.Int              `asn1:"optional"`
	CertReq    bool                  `asn1:"optional"`
	Extensions []pkix.Extension      `asn1:"optional,tag:0"`
}

func javaValidationTSAResponse(t *testing.T, pki *javaValidationPKI, request []byte, fault string) []byte {
	t.Helper()
	var req javaTestTimestampRequest
	if rest, err := asn1.Unmarshal(request, &req); err != nil || len(rest) != 0 {
		t.Fatalf("decode timestamp request: %v", err)
	}
	if req.Version != 1 || req.Nonce == nil || req.Nonce.BitLen() < 128 || !req.CertReq ||
		!req.Imprint.Algorithm.Algorithm.Equal(javaOIDSHA256) || len(req.Imprint.Digest) != sha256.Size {
		t.Fatalf("unexpected timestamp request: %#v", req)
	}
	identity := pki.tsa
	if fault == "untrusted TSA" {
		identity = pki.untrustedTSA
	}
	if fault == "wrong TSA usage" {
		identity = pki.leaf
	}
	if fault == "wrong nonce" {
		req.Nonce = new(big.Int).Add(req.Nonce, big.NewInt(1))
	}
	if fault == "missing nonce" {
		req.Nonce = nil
	}
	if fault == "wrong imprint" {
		req.Imprint.Digest[0] ^= 1
	}
	generated := pki.now
	if fault == "old token" {
		generated = generated.Add(-time.Hour)
	}
	if fault == "future token" {
		generated = generated.Add(time.Hour)
	}
	tstInfo := struct {
		Version   int
		Policy    asn1.ObjectIdentifier
		Imprint   javaTestTimestampImprint
		Serial    *big.Int
		Generated time.Time `asn1:"generalized"`
		Nonce     *big.Int  `asn1:"optional"`
	}{1, asn1.ObjectIdentifier{1, 2, 3, 4, 5}, req.Imprint, big.NewInt(101), generated, req.Nonce}
	certHash := sha256.Sum256(identity.cert.Raw)
	ess := struct{ Certs []struct{ CertHash []byte } }{Certs: []struct{ CertHash []byte }{{CertHash: certHash[:]}}}
	token := javaValidationCMS(t, identity, javaOIDTSTInfo, javaValidationASN1(t, tstInfo), []testfixture.CMSAttribute{
		javaValidationAttribute(t, javaOIDSigningCert2, ess),
	})
	if fault == "forged token" {
		token.Content.SignerInfos[0].Signature[0] ^= 1
	}
	response := struct {
		Status struct{ Value int }
		Token  asn1.RawValue `asn1:"optional"`
	}{}
	response.Token = asn1.RawValue{FullBytes: javaValidationASN1(t, token)}
	if fault == "rejected request" {
		response.Status.Value = 2
		response.Token = asn1.RawValue{}
	}
	return javaValidationASN1(t, response)
}

func javaHistoricalCRL(t *testing.T, issuer javaValidationIdentity, checkedAt time.Time, revokedSerial *big.Int, revokedAt time.Time) []byte {
	t.Helper()
	// Two minutes of publication delay stays inside the documented clock-skew
	// tolerance and lets us test a revocation just after the requested instant.
	list := &x509.RevocationList{
		Number: big.NewInt(2), ThisUpdate: checkedAt.Add(2 * time.Minute), NextUpdate: checkedAt.Add(time.Hour),
	}
	if revokedSerial != nil {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: revokedSerial, RevocationTime: revokedAt, ReasonCode: 1}}
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, issuer.cert, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type javaValidationIdentity struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

type javaValidationPKI struct {
	now           time.Time
	root          javaValidationIdentity
	intermediate  javaValidationIdentity
	leaf          javaValidationIdentity
	tsa           javaValidationIdentity
	responder     javaValidationIdentity
	rootResponder javaValidationIdentity
	untrustedTSA  javaValidationIdentity
}

var (
	javaOIDData         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	javaOIDSignedData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	javaOIDContentType  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	javaOIDMessageHash  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	javaOIDTimestamp    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	javaOIDTSTInfo      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	javaOIDSigningCert2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	javaOIDSHA256       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	javaOIDSHA1         = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	javaOIDRSA          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	javaOIDSHA256RSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

func newJavaValidationPKI(t *testing.T, serverURL string) *javaValidationPKI {
	t.Helper()
	p := &javaValidationPKI{now: time.Now().UTC().Truncate(time.Second)}
	newTemplate := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: p.now.Add(-24 * time.Hour), NotAfter: p.now.Add(24 * time.Hour),
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			OCSPServer: []string{serverURL + "/ocsp"},
		}
	}
	root := newTemplate(1, "Java integration root")
	root.IsCA, root.MaxPathLen = true, 2
	root.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	p.root = javaValidationIssue(t, root, javaValidationIdentity{})
	intermediate := newTemplate(2, "Java integration intermediate")
	intermediate.IsCA, intermediate.MaxPathLenZero = true, true
	intermediate.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	intermediate.CRLDistributionPoints = []string{serverURL + "/root.crl"}
	p.intermediate = javaValidationIssue(t, intermediate, p.root)
	leaf := newTemplate(3, "Java integration CMS signer")
	leaf.CRLDistributionPoints = []string{serverURL + "/intermediate.crl"}
	p.leaf = javaValidationIssue(t, leaf, p.intermediate)
	tsa := newTemplate(4, "Java integration TSA")
	tsa.CRLDistributionPoints = []string{serverURL + "/intermediate.crl"}
	tsa.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	tsa.ExtraExtensions = []pkix.Extension{{
		Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true,
		Value: javaValidationASN1(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}}),
	}}
	p.tsa = javaValidationIssue(t, tsa, p.intermediate)
	responder := newTemplate(5, "Java integration delegated OCSP responder")
	responder.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	responder.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}}
	p.responder = javaValidationIssue(t, responder, p.intermediate)
	rootResponder := newTemplate(7, "Java integration wrong-issuer OCSP responder")
	rootResponder.ExtKeyUsage = responder.ExtKeyUsage
	rootResponder.ExtraExtensions = responder.ExtraExtensions
	p.rootResponder = javaValidationIssue(t, rootResponder, p.root)
	untrusted := newTemplate(6, "Java integration untrusted TSA")
	untrusted.ExtKeyUsage, untrusted.ExtraExtensions = tsa.ExtKeyUsage, tsa.ExtraExtensions
	p.untrustedTSA = javaValidationIssue(t, untrusted, javaValidationIdentity{})
	return p
}

func javaValidationIssue(t *testing.T, template *x509.Certificate, issuer javaValidationIdentity) javaValidationIdentity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if issuer.cert == nil {
		issuer = javaValidationIdentity{cert: template, key: key}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return javaValidationIdentity{cert: cert, key: key}
}

func (p *javaValidationPKI) trust(t *testing.T) []kalkan.Option {
	t.Helper()
	return []kalkan.Option{
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{Path: javaIntegrationFile(t, "root.der", p.root.cert.Raw), Type: kalkan.CertificateCA}),
		kalkan.WithTrustedCertificate(kalkan.TrustedCertificate{Path: javaIntegrationFile(t, "intermediate.der", p.intermediate.cert.Raw), Type: kalkan.CertificateIntermediate}),
	}
}

func javaValidationASN1(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func javaValidationAlgorithm(oid asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
	return pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue}
}

func javaValidationAttribute(t *testing.T, oid asn1.ObjectIdentifier, value any) testfixture.CMSAttribute {
	t.Helper()
	return testfixture.CMSAttribute{Type: oid, Values: []asn1.RawValue{{FullBytes: javaValidationASN1(t, value)}}}
}

func javaValidationCMS(t *testing.T, identity javaValidationIdentity, contentType asn1.ObjectIdentifier, payload []byte, extra []testfixture.CMSAttribute) testfixture.CMSEnvelope {
	t.Helper()
	hash := sha256.Sum256(payload)
	attributes := make([]testfixture.CMSAttribute, 0, 2+len(extra))
	attributes = append(attributes,
		javaValidationAttribute(t, javaOIDContentType, contentType),
		javaValidationAttribute(t, javaOIDMessageHash, hash[:]),
	)
	attributes = append(attributes, extra...)
	encodedAttrs, err := asn1.MarshalWithParams(attributes, "set")
	if err != nil {
		t.Fatal(err)
	}
	attrsHash := sha256.Sum256(encodedAttrs)
	signature, err := rsa.SignPKCS1v15(rand.Reader, identity.key, crypto.SHA256, attrsHash[:])
	if err != nil {
		t.Fatal(err)
	}
	identifier := struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{Issuer: asn1.RawValue{FullBytes: identity.cert.RawIssuer}, Serial: identity.cert.SerialNumber}
	content := struct {
		ContentType asn1.ObjectIdentifier
		Content     []byte `asn1:"explicit,tag:0"`
	}{ContentType: contentType, Content: payload}
	version := 1
	if !contentType.Equal(javaOIDData) {
		version = 3
	}
	return testfixture.CMSEnvelope{
		ContentType: javaOIDSignedData,
		Content: testfixture.CMSSignedData{
			Version: version, DigestAlgorithms: []pkix.AlgorithmIdentifier{javaValidationAlgorithm(javaOIDSHA256)},
			ContentInfo:  asn1.RawValue{FullBytes: javaValidationASN1(t, content)},
			Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: identity.cert.Raw},
			SignerInfos: []testfixture.CMSSignerInfo{{
				Version: 1, Identifier: asn1.RawValue{FullBytes: javaValidationASN1(t, identifier)},
				DigestAlgorithm: javaValidationAlgorithm(javaOIDSHA256), SignedAttributes: attributes,
				SignatureAlgorithm: javaValidationAlgorithm(javaOIDRSA), Signature: signature,
			}},
		},
	}
}

func (p *javaValidationPKI) cms(t *testing.T, payload []byte, timestampFault string) []byte {
	t.Helper()
	envelope := javaValidationCMS(t, p.leaf, javaOIDData, payload, nil)
	if timestampFault == "none" {
		return javaValidationASN1(t, envelope)
	}
	identity := p.tsa
	switch timestampFault {
	case "untrusted TSA":
		identity = p.untrustedTSA
	case "wrong TSA usage":
		identity = p.leaf
	}
	imprint := sha256.Sum256(envelope.Content.SignerInfos[0].Signature)
	if timestampFault == "wrong imprint" {
		imprint[0] ^= 1
	}
	genTime := p.now.Add(-time.Minute)
	switch timestampFault {
	case "future token":
		genTime = p.now.Add(time.Hour)
	case "TSA expired at genTime":
		genTime = p.tsa.cert.NotBefore.Add(-time.Hour)
	}
	tstInfo := struct {
		Version int
		Policy  asn1.ObjectIdentifier
		Imprint struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
		Serial  *big.Int
		GenTime time.Time `asn1:"generalized"`
	}{Version: 1, Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Serial: big.NewInt(100), GenTime: genTime}
	tstInfo.Imprint.Algorithm, tstInfo.Imprint.Digest = javaValidationAlgorithm(javaOIDSHA256), imprint[:]
	certHash := sha256.Sum256(identity.cert.Raw)
	if timestampFault == "wrong ESS certificate" {
		certHash[0] ^= 1
	}
	ess := struct{ Certs []struct{ CertHash []byte } }{Certs: []struct{ CertHash []byte }{{CertHash: certHash[:]}}}
	token := javaValidationCMS(t, identity, javaOIDTSTInfo, javaValidationASN1(t, tstInfo), []testfixture.CMSAttribute{
		javaValidationAttribute(t, javaOIDSigningCert2, ess),
	})
	if timestampFault == "forged token signature" {
		token.Content.SignerInfos[0].Signature[0] ^= 1
	}
	encoded := javaValidationASN1(t, token)
	envelope.Content.SignerInfos[0].UnsignedAttributes = []testfixture.CMSAttribute{{
		Type: javaOIDTimestamp, Values: []asn1.RawValue{{FullBytes: encoded}},
	}}
	return javaValidationASN1(t, envelope)
}

type javaValidationOCSPCertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

type javaValidationOCSPRequest struct {
	TBS struct {
		Version       int           `asn1:"optional,explicit,tag:0,default:0"`
		RequestorName asn1.RawValue `asn1:"optional,explicit,tag:1"`
		Requests      []struct {
			CertID     javaValidationOCSPCertID
			Extensions []pkix.Extension `asn1:"optional,explicit,tag:0"`
		}
		Extensions []pkix.Extension `asn1:"optional,explicit,tag:2"`
	}
	Signature asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type javaValidationOCSPSingle struct {
	CertID     javaValidationOCSPCertID
	Status     asn1.RawValue
	ThisUpdate time.Time `asn1:"generalized"`
	NextUpdate time.Time `asn1:"optional,explicit,tag:0,generalized"`
}

func (p *javaValidationPKI) ocsp(request []byte, fault string) ([]byte, error) {
	var req javaValidationOCSPRequest
	if rest, err := asn1.Unmarshal(request, &req); err != nil || len(rest) != 0 || len(req.TBS.Requests) != 1 {
		return nil, fmt.Errorf("invalid OCSP request: %w", err)
	}
	certID := req.TBS.Requests[0].CertID
	issuer := p.intermediate
	if certID.SerialNumber.Cmp(p.intermediate.cert.SerialNumber) == 0 {
		issuer = p.root
	}
	// Verify that the test server received a request for the correct issuer;
	// echoing an arbitrary CertID would miss client-side request bugs.
	wantName, wantKey, err := javaValidationIssuerHashes(issuer.cert, certID.HashAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certID.IssuerNameHash, wantName) || !bytes.Equal(certID.IssuerKeyHash, wantKey) {
		return nil, errors.New("OCSP request contains incorrect issuer hashes")
	}
	if certID.SerialNumber.Cmp(p.leaf.cert.SerialNumber) != 0 && fault != "revoked intermediate" && fault != "revoked TSA" {
		fault = "good"
	}
	if fault == "revoked intermediate" && certID.SerialNumber.Cmp(p.intermediate.cert.SerialNumber) != 0 {
		fault = "good"
	}
	if fault == "revoked TSA" && certID.SerialNumber.Cmp(p.tsa.cert.SerialNumber) != 0 {
		fault = "good"
	}
	responseSigner := issuer
	switch fault {
	case "delegated good", "delegated expired then valid", "delegated future then valid",
		"delegated not valid at producedAt then valid", "delegated expired only",
		"delegated future only", "delegated not valid at producedAt only",
		"delegated wrong usage then valid", "delegated wrong usage only":
		responseSigner = p.responder
	case "unauthorized responder":
		responseSigner = p.leaf
	case "delegated wrong issuer":
		responseSigner = p.rootResponder
	}
	thisUpdate, nextUpdate := p.now.Add(-time.Minute), p.now.Add(time.Hour)
	switch fault {
	case "stale":
		thisUpdate, nextUpdate = p.now.Add(-2*time.Hour), p.now.Add(-time.Hour)
	case "future thisUpdate":
		thisUpdate, nextUpdate = p.now.Add(time.Hour), p.now.Add(2*time.Hour)
	}
	status := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0}
	switch fault {
	case "unknown":
		status.Tag = 2
	case "revoked", "revoked intermediate", "revoked TSA":
		revoked, err := asn1.Marshal(struct {
			Time time.Time `asn1:"generalized"`
		}{p.now.Add(-time.Hour)})
		if err != nil {
			return nil, err
		}
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(revoked, &raw); err != nil {
			return nil, err
		}
		status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: raw.Bytes}
	}
	switch fault {
	case "wrong certificate":
		certID.SerialNumber = big.NewInt(99999)
	case "wrong issuer":
		certID.IssuerNameHash = bytes.Clone(certID.IssuerNameHash)
		certID.IssuerNameHash[0] ^= 1
	}
	responseData := struct {
		ResponderID asn1.RawValue
		ProducedAt  time.Time `asn1:"generalized"`
		Responses   []javaValidationOCSPSingle
		Extensions  []pkix.Extension `asn1:"optional,explicit,tag:1"`
	}{
		ResponderID: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: responseSigner.cert.RawSubject},
		ProducedAt:  p.now.Add(-30 * time.Second),
		Responses:   []javaValidationOCSPSingle{{CertID: certID, Status: status, ThisUpdate: thisUpdate, NextUpdate: nextUpdate}},
		Extensions:  req.TBS.Extensions,
	}
	switch fault {
	case "missing nonce":
		responseData.Extensions = nil
	case "wrong nonce":
		responseData.Extensions = append([]pkix.Extension(nil), responseData.Extensions...)
		for i := range responseData.Extensions {
			if responseData.Extensions[i].Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}) {
				responseData.Extensions[i].Value = bytes.Clone(responseData.Extensions[i].Value)
				responseData.Extensions[i].Value[len(responseData.Extensions[i].Value)-1] ^= 1
			}
		}
	}
	tbs, err := asn1.Marshal(responseData)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(tbs)
	signature, err := rsa.SignPKCS1v15(rand.Reader, responseSigner.key, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	if fault == "forged signature" {
		signature[0] ^= 1
	}
	embeddedCertificates, err := p.ocspResponderCertificates(responseSigner, issuer, fault)
	if err != nil {
		return nil, err
	}
	basic, err := asn1.Marshal(struct {
		TBS          asn1.RawValue
		Algorithm    pkix.AlgorithmIdentifier
		Signature    asn1.BitString
		Certificates []asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}{
		TBS: asn1.RawValue{FullBytes: tbs}, Algorithm: javaValidationAlgorithm(javaOIDSHA256RSA),
		Signature:    asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
		Certificates: embeddedCertificates,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Status asn1.Enumerated
		Bytes  struct {
			Type     asn1.ObjectIdentifier
			Response []byte
		} `asn1:"explicit,tag:0"`
	}{Status: 0, Bytes: struct {
		Type     asn1.ObjectIdentifier
		Response []byte
	}{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}, Response: basic}})
}

func (p *javaValidationPKI) ocspResponderCertificates(responder, issuer javaValidationIdentity, fault string) ([]asn1.RawValue, error) {
	certificates := []asn1.RawValue{{FullBytes: responder.cert.Raw}}
	invalid := *responder.cert
	switch fault {
	case "delegated expired then valid", "delegated expired only":
		invalid.NotBefore = p.now.Add(-48 * time.Hour)
		invalid.NotAfter = p.now.Add(-24 * time.Hour)
	case "delegated future then valid", "delegated future only":
		invalid.NotBefore = p.now.Add(24 * time.Hour)
		invalid.NotAfter = p.now.Add(48 * time.Hour)
	case "delegated not valid at producedAt then valid", "delegated not valid at producedAt only":
		// Valid now, but not at producedAt (30 seconds before p.now).
		invalid.NotBefore = p.now.Add(-10 * time.Second)
	case "delegated wrong usage then valid", "delegated wrong usage only":
		invalid.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return certificates, nil
	}
	// Renew the certificate with the same subject and key: both candidates match
	// ResponderID and verify the response, so selection must consider authorization
	// and validity before choosing a certificate.
	invalid.SerialNumber = big.NewInt(9001)
	der, err := x509.CreateCertificate(rand.Reader, &invalid, issuer.cert, &responder.key.PublicKey, issuer.key)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(fault, " then valid") {
		certificates = nil
	}
	return append([]asn1.RawValue{{FullBytes: der}}, certificates...), nil
}

func javaValidationIssuerHashes(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, []byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, nil, err
	}
	if oid.Equal(javaOIDSHA1) {
		name, key := sha1.Sum(cert.RawSubject), sha1.Sum(spki.Key.RightAlign())
		return name[:], key[:], nil
	}
	if oid.Equal(javaOIDSHA256) {
		name, key := sha256.Sum256(cert.RawSubject), sha256.Sum256(spki.Key.RightAlign())
		return name[:], key[:], nil
	}
	return nil, nil, fmt.Errorf("unsupported test OCSP request hash %s", oid)
}

func (p *javaValidationPKI) crl(t *testing.T, issuer javaValidationIdentity, fault string) []byte {
	t.Helper()
	template := &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: p.now.Add(-time.Minute), NextUpdate: p.now.Add(time.Hour),
	}
	switch fault {
	case "stale":
		template.ThisUpdate, template.NextUpdate = p.now.Add(-2*time.Hour), p.now.Add(-time.Hour)
	case "future thisUpdate":
		template.ThisUpdate, template.NextUpdate = p.now.Add(time.Hour), p.now.Add(2*time.Hour)
	}
	if fault == "revoked" || fault == "revoked intermediate" || fault == "revoked TSA" {
		serial := p.leaf.cert.SerialNumber
		switch fault {
		case "revoked intermediate":
			serial = p.intermediate.cert.SerialNumber
		case "revoked TSA":
			serial = p.tsa.cert.SerialNumber
		}
		template.RevokedCertificateEntries = []x509.RevocationListEntry{{
			SerialNumber: serial, RevocationTime: p.now.Add(-time.Hour), ReasonCode: 1,
		}}
	}
	if fault == "wrong issuer" {
		issuer = p.root
	}
	switch fault {
	case "delta CRL":
		template.ExtraExtensions = []pkix.Extension{{
			Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: javaValidationASN1(t, big.NewInt(0)),
		}}
	case "indirect CRL":
		template.ExtraExtensions = []pkix.Extension{{
			Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true,
			Value: javaValidationASN1(t, struct {
				Indirect bool `asn1:"optional,tag:4"`
			}{Indirect: true}),
		}}
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, issuer.cert, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	if fault == "forged signature" {
		der[len(der)-1] ^= 1
	}
	return der
}

func javaValidationResign(t *testing.T, identity javaValidationIdentity, signer *testfixture.CMSSignerInfo, payload []byte) {
	t.Helper()
	input := payload
	if signer.SignedAttributes != nil {
		var err error
		input, err = asn1.MarshalWithParams(signer.SignedAttributes, "set")
		if err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(input)
	var err error
	signer.Signature, err = rsa.SignPKCS1v15(rand.Reader, identity.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
}

func javaValidationNumberedCRL(t *testing.T, issuer javaValidationIdentity, number int64, updated, next time.Time, revoked *big.Int) []byte {
	t.Helper()
	list := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: updated, NextUpdate: next}
	if revoked != nil {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: revoked, RevocationTime: updated.Add(-time.Minute), ReasonCode: 1}}
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, issuer.cert, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
