package kalkan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6960 requires SHA-1 for ResponderID byKey.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// testOCSPPKI contains a CA, its leaf certificate, and OCSP responders: a delegated responder,
// one without id-kp-OCSPSigning, one issued by another CA, and one that has expired.
type testOCSPPKI struct {
	ca, leaf, responder, withoutUsage, foreign, expired *x509.Certificate
	caKey, responderKey                                 *ecdsa.PrivateKey
}

func newTestOCSPPKI(t *testing.T) testOCSPPKI {
	t.Helper()

	now := time.Now()
	pki := testOCSPPKI{caKey: ocspTestKey(t), responderKey: ocspTestKey(t)}
	otherKey := ocspTestKey(t)
	pki.ca = issueTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, pki.caKey, pki.caKey)
	other := issueTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Other CA"},
		NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, otherKey, otherKey)
	pki.leaf = issueTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Leaf"},
		NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(time.Hour),
	}, pki.ca, ocspTestKey(t), pki.caKey)

	responder := func(serial int64, parent *x509.Certificate, signer *ecdsa.PrivateKey, usage []x509.ExtKeyUsage, notAfter time.Time) *x509.Certificate {
		return issueTestCertificate(t, &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Responder"},
			NotBefore: now.Add(-2 * time.Hour), NotAfter: notAfter, ExtKeyUsage: usage,
		}, parent, pki.responderKey, signer)
	}

	signing := []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	pki.responder = responder(4, pki.ca, pki.caKey, signing, now.Add(time.Hour))
	pki.withoutUsage = responder(5, pki.ca, pki.caKey, nil, now.Add(time.Hour))
	pki.foreign = responder(6, other, otherKey, signing, now.Add(time.Hour))
	pki.expired = responder(7, pki.ca, pki.caKey, signing, now.Add(-time.Hour))

	return pki
}

// answer creates an OCSP response for the leaf, signed by responder's key and embedding its
// certificate. With a nil responder, the response is signed by the CA itself.
func (pki testOCSPPKI) answer(t *testing.T, responder *x509.Certificate, template testOCSPResponse) []byte {
	t.Helper()

	if template.SerialNumber == nil {
		template.SerialNumber = pki.leaf.SerialNumber
	}

	signer, key := pki.ca, pki.caKey
	if responder != nil {
		signer, key = responder, pki.responderKey
	}
	id := pki.certID(t)
	id.SerialNumber = template.SerialNumber
	status := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: template.Status}
	if template.Status == testOCSPRevoked {
		status.FullBytes = ocspTestMarshal(t, struct {
			Time time.Time `asn1:"generalized"`
		}{template.RevokedAt})
		status.FullBytes[0] = 0xa1
	}
	basic := ocspBasicResponse{
		TBSResponseData: ocspResponseData{
			ResponderID: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: signer.RawSubject},
			ProducedAt:  time.Now().UTC().Truncate(time.Second),
			Responses:   []ocspSingleResponse{{CertID: id, CertStatus: status, ThisUpdate: template.ThisUpdate, NextUpdate: template.NextUpdate, Extensions: template.ExtraExtensions}},
		},
	}
	if responder != nil {
		basic.Certificates = []asn1.RawValue{{FullBytes: responder.Raw}}
	}
	return signOCSPTestResponse(t, basic, key)
}

const (
	testOCSPGood = iota
	testOCSPRevoked
	testOCSPUnknown
)

type testOCSPResponse struct {
	Status                            int
	SerialNumber                      *big.Int
	ThisUpdate, NextUpdate, RevokedAt time.Time
	ExtraExtensions                   []pkix.Extension
}

func ocspTestMarshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signOCSPTestResponse(t *testing.T, basic ocspBasicResponse, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	basic.TBSResponseData.Raw = nil
	basic.TBSResponseData.Raw = ocspTestMarshal(t, basic.TBSResponseData)
	return ocspTestSignRawResponse(t, basic, key)
}

func ocspTestSignRawResponse(t *testing.T, basic ocspBasicResponse, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	signed := []byte(basic.TBSResponseData.Raw)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	basic.SignatureAlgorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	basic.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	var response ocspResponse
	response.Bytes.Type = oidOCSPBasic
	response.Bytes.Response = ocspTestMarshal(t, basic)
	return ocspTestMarshal(t, response)
}

func (pki testOCSPPKI) certID(t *testing.T) ocspCertID {
	t.Helper()

	id, err := kalkanOCSPCertID(pki.leaf.SerialNumber, pki.ca)
	if err != nil {
		t.Fatal(err)
	}

	return id
}

// Fixtures were produced by golang.org/x/crypto/ocsp v0.57.0, independently
// of this implementation. They require no external module to run the tests.
func TestOCSPInteroperability(t *testing.T) {
	issuer := readTestCertificate(t, "testdata/ocsp/issuer.der")
	leaf := readTestCertificate(t, "testdata/ocsp/leaf.der")
	id, err := kalkanOCSPCertID(leaf.SerialNumber, issuer)
	if err != nil {
		t.Fatal(err)
	}
	request, err := kalkanOCSPRequest(id)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/ocsp/request.der")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(request, want) {
		t.Fatalf("request differs from independent fixture: %x != %x", request, want)
	}
	response, err := os.ReadFile("testdata/ocsp/good.der")
	if err != nil {
		t.Fatal(err)
	}
	_, revoked, err := kalkanOCSPStatus(response, id, issuer, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || revoked {
		t.Fatalf("independent response: revoked=%t, err=%v", revoked, err)
	}
}

// Accept only fresh responses for the requested certificate signed by its CA or a delegated
// responder. Unknown status, critical extensions, and responder refusal do not establish status.
func TestKalkanOCSPStatus(t *testing.T) {
	t.Parallel()

	pki := newTestOCSPPKI(t)
	now := time.Now()
	fresh := testOCSPResponse{Status: testOCSPGood, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	with := func(change func(*testOCSPResponse)) testOCSPResponse {
		template := fresh
		change(&template)

		return template
	}

	tampered := pki.answer(t, nil, fresh)
	tampered[len(tampered)-1] ^= 1

	tests := []struct {
		name    string
		answer  []byte
		revoked bool
		refusal string
	}{
		{name: "good from the delegated responder", answer: pki.answer(t, pki.responder, fresh)},
		{name: "good signed by the CA", answer: pki.answer(t, nil, fresh)},
		{
			name:    "revoked",
			answer:  pki.answer(t, pki.responder, with(func(r *testOCSPResponse) { r.Status, r.RevokedAt = testOCSPRevoked, now.Add(-time.Hour) })),
			revoked: true,
		},
		{
			name:    "unknown",
			answer:  pki.answer(t, pki.responder, with(func(r *testOCSPResponse) { r.Status = testOCSPUnknown })),
			refusal: "does not know",
		},
		{name: "responder without id-kp-OCSPSigning", answer: pki.answer(t, pki.withoutUsage, fresh), refusal: "signed neither"},
		{name: "responder of another CA", answer: pki.answer(t, pki.foreign, fresh), refusal: "signed neither"},
		{name: "expired responder", answer: pki.answer(t, pki.expired, fresh), refusal: "signed neither"},
		{name: "tampered signature", answer: tampered, refusal: "signed neither"},
		{
			name:    "another certificate",
			answer:  pki.answer(t, pki.responder, with(func(r *testOCSPResponse) { r.SerialNumber = big.NewInt(99) })),
			refusal: "no status",
		},
		{
			name:    "stale",
			answer:  pki.answer(t, pki.responder, with(func(r *testOCSPResponse) { r.ThisUpdate, r.NextUpdate = now.Add(-2*time.Hour), now.Add(-time.Hour) })),
			refusal: "stale",
		},
		{
			name:    "from the future",
			answer:  pki.answer(t, pki.responder, with(func(r *testOCSPResponse) { r.ThisUpdate, r.NextUpdate = now.Add(time.Hour), now.Add(2*time.Hour) })),
			refusal: "future",
		},
		{
			name:   "fresh without nextUpdate",
			answer: pki.answer(t, pki.responder, with(func(r *testOCSPResponse) { r.ThisUpdate, r.NextUpdate = now.Add(-10*time.Minute), time.Time{} })),
		},
		{
			name:    "old without nextUpdate",
			answer:  pki.answer(t, pki.responder, with(func(r *testOCSPResponse) { r.ThisUpdate, r.NextUpdate = now.Add(-2*time.Hour), time.Time{} })),
			refusal: "stale",
		},
		{
			name: "critical extension",
			answer: pki.answer(t, pki.responder, with(func(r *testOCSPResponse) {
				r.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Critical: true, Value: []byte{5, 0}}}
			})),
			refusal: "critical extension",
		},
		{name: "try later", answer: []byte{0x30, 3, 0x0a, 1, 3}, refusal: "responseStatus 3"},
		{name: "not an OCSP response", answer: []byte("<html>proxy error</html>"), refusal: "not an OCSP response"},
	}

	for _, test := range tests {
		revokedAt, revoked, err := kalkanOCSPStatus(test.answer, pki.certID(t), pki.ca, now)

		switch {
		case test.refusal != "" && (err == nil || !strings.Contains(err.Error(), test.refusal)):
			t.Errorf("%s: kalkanOCSPStatus() = %v, want a refusal with %q", test.name, err, test.refusal)
		case test.refusal == "" && (err != nil || revoked != test.revoked):
			t.Errorf("%s: kalkanOCSPStatus() = revoked %t, %v; want revoked %t", test.name, revoked, err, test.revoked)
		case test.revoked && !revokedAt.Equal(now.Add(-time.Hour).Truncate(time.Second)):
			t.Errorf("%s: revoked at %s, want %s", test.name, revokedAt, now.Add(-time.Hour))
		}
	}
}

// issueTestCertificate issues template with key, signed by signer on behalf of parent.
// With a nil parent, the certificate is self-signed.
func issueTestCertificate(t *testing.T, template, parent *x509.Certificate, key, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	if parent == nil {
		parent = template
	}
	template.AuthorityKeyId = parent.SubjectKeyId

	raw, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}

	return certificate
}

func readTestCertificate(t testing.TB, path string) *x509.Certificate {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}

	return certificate
}

func ocspTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestOCSPRejectsSignedMalformedResponses(t *testing.T) {
	pki := newTestOCSPPKI(t)
	now := time.Now()
	raw := pki.answer(t, nil, testOCSPResponse{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)})
	var response ocspResponse
	if _, err := asn1.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*ocspBasicResponse)
	}{
		{"version", func(b *ocspBasicResponse) { b.TBSResponseData.Version = 1 }},
		{"produced in future", func(b *ocspBasicResponse) { b.TBSResponseData.ProducedAt = now.Add(time.Hour) }},
		{"wrong responder name", func(b *ocspBasicResponse) {
			b.TBSResponseData.ResponderID.Bytes = pki.leaf.RawSubject
			b.TBSResponseData.ResponderID.FullBytes = nil
		}},
		{"wrong responder hash", func(b *ocspBasicResponse) {
			b.TBSResponseData.ResponderID = asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: ocspTestMarshal(t, make([]byte, 20))}
		}},
		{"duplicate status", func(b *ocspBasicResponse) {
			b.TBSResponseData.Responses = append(b.TBSResponseData.Responses, b.TBSResponseData.Responses[0])
		}},
		{"reversed update times", func(b *ocspBasicResponse) {
			b.TBSResponseData.Responses[0].NextUpdate = b.TBSResponseData.Responses[0].ThisUpdate
		}},
		{"nonempty good status", func(b *ocspBasicResponse) {
			b.TBSResponseData.Responses[0].CertStatus = asn1.RawValue{Class: 2, Tag: 0, Bytes: []byte{0}}
		}},
		{"unknown status tag", func(b *ocspBasicResponse) {
			b.TBSResponseData.Responses[0].CertStatus = asn1.RawValue{Class: 2, Tag: 3}
		}},
		{"critical response extension", func(b *ocspBasicResponse) {
			b.TBSResponseData.Extensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Critical: true, Value: []byte{5, 0}}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var basic ocspBasicResponse
			if _, err := asn1.Unmarshal(response.Bytes.Response, &basic); err != nil {
				t.Fatal(err)
			}
			test.change(&basic)
			if _, _, err := kalkanOCSPStatus(signOCSPTestResponse(t, basic, pki.caKey), pki.certID(t), pki.ca, now); err == nil {
				t.Fatal("accepted malformed signed response")
			}
		})
	}
	var basic ocspBasicResponse
	if _, err := asn1.Unmarshal(response.Bytes.Response, &basic); err != nil {
		t.Fatal(err)
	}
	basic.TBSResponseData.ResponderID = asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: ocspTestMarshal(t, pki.certID(t).IssuerKeyHash)}
	if _, revoked, err := kalkanOCSPStatus(signOCSPTestResponse(t, basic, pki.caKey), pki.certID(t), pki.ca, now); err != nil || revoked {
		t.Fatalf("byKey response=%t,%v", revoked, err)
	}
}

func TestOCSPDelegatedResponderByKey(t *testing.T) {
	pki := newTestOCSPPKI(t)
	now := time.Now()
	raw := pki.answer(t, pki.responder, testOCSPResponse{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)})
	var response ocspResponse
	if _, err := asn1.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}

	// Derive the expected KeyHash independently from the responder's public key,
	// without calling kalkanOCSPPublicKeyHash or kalkanOCSPCertID.
	spki, err := x509.MarshalPKIXPublicKey(pki.responder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &key); err != nil {
		t.Fatal(err)
	}
	responderHash := sha1.Sum(key.PublicKey.Bytes) // #nosec G401 -- OCSP key identifier, not a signature.
	id := pki.certID(t)
	if slices.Equal(responderHash[:], id.IssuerKeyHash) {
		t.Fatal("test responder and CA must have different public keys")
	}

	for _, test := range []struct {
		name  string
		hash  []byte
		valid bool
	}{
		{name: "responder key hash", hash: responderHash[:], valid: true},
		{name: "issuer key hash", hash: id.IssuerKeyHash},
	} {
		t.Run(test.name, func(t *testing.T) {
			var basic ocspBasicResponse
			if _, err := asn1.Unmarshal(response.Bytes.Response, &basic); err != nil {
				t.Fatal(err)
			}
			basic.TBSResponseData.ResponderID = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: ocspTestMarshal(t, test.hash)}
			_, revoked, err := kalkanOCSPStatus(signOCSPTestResponse(t, basic, pki.responderKey), id, pki.ca, now)
			if test.valid {
				if err != nil || revoked {
					t.Fatalf("delegated byKey response: revoked=%t, error=%v", revoked, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "signed neither") {
				t.Fatalf("wrong responder key hash: error=%v, want signer rejection", err)
			}
		})
	}
}

func TestOCSPResponderCertificateRestrictions(t *testing.T) {
	pki := newTestOCSPPKI(t)
	now := time.Now()
	for _, critical := range []bool{false, true} {
		template := *pki.responder
		if critical {
			template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Critical: true, Value: []byte{5, 0}}}
		} else {
			template.KeyUsage = x509.KeyUsageCRLSign
		}
		responder := issueTestCertificate(t, &template, pki.ca, pki.responderKey, pki.caKey)
		answer := pki.answer(t, responder, testOCSPResponse{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)})
		if _, _, err := kalkanOCSPStatus(answer, pki.certID(t), pki.ca, now); err == nil {
			t.Fatalf("accepted responder critical=%t", critical)
		}
	}
}

func TestOCSPResponderWithNegativeSerial(t *testing.T) {
	pki := newTestOCSPPKI(t)
	now := time.Now()
	der, _ := ocspTestNegativeSerialCertificate(t, pki.responder, pki.caKey)
	tampered := slices.Clone(der)
	tampered[len(tampered)-1] ^= 1
	for _, test := range []struct {
		name  string
		der   []byte
		valid bool
	}{
		{name: "signed certificate", der: der, valid: true},
		{name: "tampered certificate signature", der: tampered},
	} {
		t.Run(test.name, func(t *testing.T) {
			responder, err := parseOCSPDERCertificate(test.der)
			if err != nil {
				t.Fatal(err)
			}
			answer := pki.answer(t, responder, testOCSPResponse{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)})
			_, revoked, err := kalkanOCSPStatus(answer, pki.certID(t), pki.ca, now)
			if (err == nil) != test.valid || revoked {
				t.Fatalf("negative-serial responder status = revoked %t, error %v; want valid %t", revoked, err, test.valid)
			}
		})
	}
}

// These certificates and responses were signed and verified independently by
// KalkanCrypt 0.7.5, rather than by the verifier exercised here.
func TestOCSPGOST2015Digest256(t *testing.T) {
	issuer := readTestCertificate(t, "testdata/ocsp/gost2015_256/gost256-ca.der")
	leaf := readTestCertificate(t, "testdata/ocsp/gost2015_256/gost256-leaf.der")
	if err := checkOCSPIssuer(leaf, issuer); err != nil {
		t.Fatalf("GOST-256 leaf certificate signature: %v", err)
	}
	id, err := kalkanOCSPCertID(leaf.SerialNumber, issuer)
	if err != nil {
		t.Fatal(err)
	}
	// Check the SDK fixture's signed freshness window at a fixed instant.
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	delegated := readGOST256OCSPFixture(t, "gost256-ocsp-delegated-good.der")
	var response ocspResponse
	if _, err := asn1.Unmarshal(delegated, &response); err != nil {
		t.Fatal(err)
	}
	var basic ocspBasicResponse
	if _, err := asn1.Unmarshal(response.Bytes.Response, &basic); err != nil {
		t.Fatal(err)
	}
	if !basic.SignatureAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 1}) || len(basic.Signature.Bytes) != 64 || len(basic.Certificates) != 1 {
		t.Fatal("fixture must contain a GOST-2015/256 response and delegated responder")
	}
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "issuer", raw: readGOST256OCSPFixture(t, "gost256-ocsp-ca-good.der")},
		{name: "delegated responder", raw: delegated},
	} {
		t.Run(test.name, func(t *testing.T) {
			if revokedAt, revoked, err := kalkanOCSPStatus(test.raw, id, issuer, now); err != nil || revoked || !revokedAt.IsZero() {
				t.Fatalf("independently signed good response: revoked=%t, at=%v, error=%v", revoked, revokedAt, err)
			}
		})
	}

	alter := func(change func(*ocspBasicResponse)) []byte {
		t.Helper()
		var changed ocspBasicResponse
		if _, err := asn1.Unmarshal(response.Bytes.Response, &changed); err != nil {
			t.Fatal(err)
		}
		change(&changed)
		outer := response
		outer.Bytes.Response = ocspTestMarshal(t, changed)
		return ocspTestMarshal(t, outer)
	}
	wrongKey := *issuer
	wrongKey.RawSubjectPublicKeyInfo = leaf.RawSubjectPublicKeyInfo
	if slices.Equal(issuer.RawSubjectPublicKeyInfo, wrongKey.RawSubjectPublicKeyInfo) {
		t.Fatal("issuer and leaf fixtures must have independent keys")
	}
	wrongUsage := *issuer
	wrongUsage.KeyUsage = x509.KeyUsageDigitalSignature
	for _, test := range []struct {
		name   string
		raw    []byte
		issuer *x509.Certificate
	}{
		{name: "altered signed response", raw: alter(func(b *ocspBasicResponse) {
			b.TBSResponseData.Raw = nil
			b.TBSResponseData.ProducedAt = b.TBSResponseData.ProducedAt.Add(time.Second)
		})},
		{name: "altered response signature", raw: alter(func(b *ocspBasicResponse) {
			b.Signature.Bytes = slices.Clone(b.Signature.Bytes)
			b.Signature.Bytes[0] ^= 1
		})},
		{name: "altered responder certificate signature", raw: alter(func(b *ocspBasicResponse) {
			certificate := slices.Clone(b.Certificates[0].FullBytes)
			certificate[len(certificate)-1] ^= 1
			b.Certificates = []asn1.RawValue{{FullBytes: certificate}}
		})},
		{name: "missing delegated certificate", raw: alter(func(b *ocspBasicResponse) { b.Certificates = nil })},
		{name: "responder without OCSP signing usage", raw: readGOST256OCSPFixture(t, "gost256-ocsp-without-eku.der")},
		{name: "responder issued by another CA", raw: readGOST256OCSPFixture(t, "gost256-ocsp-foreign-issuer.der")},
		{name: "wrong issuer public key", raw: delegated, issuer: &wrongKey},
		{name: "issuer without certificate signing usage", raw: delegated, issuer: &wrongUsage},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer := test.issuer
			if signer == nil {
				signer = issuer
			}
			if _, _, err := kalkanOCSPStatus(test.raw, id, signer, now); err == nil || !strings.Contains(err.Error(), "signed neither") {
				t.Fatalf("unauthenticated or unauthorized responder accepted: %v", err)
			}
		})
	}
}

func readGOST256OCSPFixture(t testing.TB, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/ocsp/gost2015_256/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Unknown ASN.1 fields must not disappear when a fixed schema is decoded into
// a Go struct. In particular, envelope fields are outside the signed bytes.
func TestOCSPRejectsUnexpectedASN1Fields(t *testing.T) {
	issuer := readTestCertificate(t, "testdata/ocsp/gost2015_256/gost256-ca.der")
	leaf := readTestCertificate(t, "testdata/ocsp/gost2015_256/gost256-leaf.der")
	id, err := kalkanOCSPCertID(leaf.SerialNumber, issuer)
	if err != nil {
		t.Fatal(err)
	}
	testOCSPRejectsUnexpectedEnvelopeFields(t, readGOST256OCSPFixture(t, "gost256-ocsp-delegated-good.der"), id, issuer,
		time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))

	pki := newTestOCSPPKI(t)
	now := time.Now()
	raw := pki.answer(t, nil, testOCSPResponse{
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte{5, 0}}},
	})
	var response ocspResponse
	if _, err := asn1.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	var basic ocspBasicResponse
	if _, err := asn1.Unmarshal(response.Bytes.Response, &basic); err != nil {
		t.Fatal(err)
	}
	basic.TBSResponseData.Raw = nil
	basic.TBSResponseData.Extensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte{5, 0}}}
	basic.TBSResponseData.Raw = ocspTestMarshal(t, basic.TBSResponseData)
	if _, revoked, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, basic, pki.caKey), pki.certID(t), pki.ca, now); err != nil || revoked {
		t.Fatalf("valid signed structure control: revoked=%t, error=%v", revoked, err)
	}
	for _, test := range []struct {
		name string
		path []int
	}{
		{"response data", nil},
		{"single response", []int{2, 0}},
		{"certificate ID", []int{2, 0, 0}},
		{"hash algorithm", []int{2, 0, 0, 0}},
		{"responder explicit wrapper", []int{0}},
		{"next update explicit wrapper", []int{2, 0, 3}},
		{"response extensions explicit wrapper", []int{3}},
		{"response extension", []int{3, 0, 0}},
		{"single extensions explicit wrapper", []int{2, 0, 4}},
		{"single extension", []int{2, 0, 4, 0, 0}},
	} {
		t.Run("signed "+test.name, func(t *testing.T) {
			altered := basic
			altered.TBSResponseData.Raw = ocspTestASN1Change(t, basic.TBSResponseData.Raw, test.path, func(value asn1.RawValue) asn1.RawValue {
				value.Bytes = append(slices.Clone(value.Bytes), 2, 1, 1)
				return value
			})
			if _, _, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, altered, pki.caKey), pki.certID(t), pki.ca, now); err == nil {
				t.Fatal("accepted an unexpected field covered by a valid signature")
			}
		})
	}
	t.Run("signed non-NULL hash parameters", func(t *testing.T) {
		altered := basic
		altered.TBSResponseData.Raw = ocspTestASN1Change(t, basic.TBSResponseData.Raw, []int{2, 0, 0, 0}, func(value asn1.RawValue) asn1.RawValue {
			value.Bytes = append(slices.Clone(value.Bytes[:len(value.Bytes)-2]), 2, 1, 1)
			return value
		})
		if _, _, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, altered, pki.caKey), pki.certID(t), pki.ca, now); err == nil {
			t.Fatal("accepted non-NULL hash parameters covered by a valid signature")
		}
	})
}

func TestOCSPPreservesAcceptedASN1Representations(t *testing.T) {
	pki := newTestOCSPPKI(t)
	now := time.Now()
	raw := pki.answer(t, nil, testOCSPResponse{
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte{5, 0}}},
	})
	var response ocspResponse
	if _, err := asn1.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	var basic ocspBasicResponse
	if _, err := asn1.Unmarshal(response.Bytes.Response, &basic); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		path   []int
		change func(asn1.RawValue) asn1.RawValue
	}{
		{"explicit version default", nil, func(value asn1.RawValue) asn1.RawValue {
			value.Bytes = append([]byte{0xa0, 3, 2, 1, 0}, value.Bytes...)
			return value
		}},
		{"omitted hash parameters", []int{2, 0, 0, 0}, func(value asn1.RawValue) asn1.RawValue {
			var oid asn1.RawValue
			if _, err := asn1.Unmarshal(value.Bytes, &oid); err != nil {
				t.Fatal(err)
			}
			value.Bytes = oid.FullBytes
			return value
		}},
		{"fractional generalized time", []int{1}, func(value asn1.RawValue) asn1.RawValue {
			value.Bytes = []byte(basic.TBSResponseData.ProducedAt.Format("20060102150405") + ".125Z")
			return value
		}},
		{"generalized time with offset", []int{1}, func(value asn1.RawValue) asn1.RawValue {
			value.Bytes = []byte(basic.TBSResponseData.ProducedAt.In(time.FixedZone("UTC+1", 3600)).Format("20060102150405-0700"))
			return value
		}},
		{"explicit noncritical default", []int{2, 0, 4, 0, 0}, func(value asn1.RawValue) asn1.RawValue {
			var oid asn1.RawValue
			rest, err := asn1.Unmarshal(value.Bytes, &oid)
			if err != nil {
				t.Fatal(err)
			}
			value.Bytes = append(append(slices.Clone(oid.FullBytes), 1, 1, 0), rest...)
			return value
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			altered := basic
			altered.TBSResponseData.Raw = ocspTestASN1Change(t, basic.TBSResponseData.Raw, test.path, test.change)
			if _, revoked, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, altered, pki.caKey), pki.certID(t), pki.ca, now); err != nil || revoked {
				t.Fatalf("equivalent signed representation: revoked=%t, error=%v", revoked, err)
			}
		})
	}
}

func TestOCSPRejectsMalformedUnselectedFields(t *testing.T) {
	pki := newTestOCSPPKI(t)
	now := time.Now()
	raw := pki.answer(t, nil, testOCSPResponse{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)})
	var response ocspResponse
	if _, err := asn1.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	var basic ocspBasicResponse
	if _, err := asn1.Unmarshal(response.Bytes.Response, &basic); err != nil {
		t.Fatal(err)
	}
	withCertificate := basic
	negativeSerial, _ := ocspTestNegativeSerialCertificate(t, pki.responder, pki.caKey)
	for _, certificate := range [][]byte{pki.responder.Raw, negativeSerial} {
		withCertificate.Certificates = []asn1.RawValue{{FullBytes: certificate}}
		if _, revoked, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, withCertificate, pki.caKey), pki.certID(t), pki.ca, now); err != nil || revoked {
			t.Fatalf("valid unused certificate control: revoked=%t, error=%v", revoked, err)
		}
	}
	for _, test := range []struct {
		name string
		path []int
	}{
		{"unaligned unused certificate signature", []int{2}},
		{"unaligned unused certificate public key", []int{0, 6, 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			malformed := ocspTestASN1Change(t, pki.responder.Raw, test.path, func(value asn1.RawValue) asn1.RawValue {
				// Shift left by one bit. RightAlign restores the ECDSA signature
				// or EC point: their initial SEQUENCE/point tags have zero high bits.
				value.Bytes = slices.Clone(value.Bytes)
				value.Bytes[0] = 1
				for i := 1; i < len(value.Bytes); i++ {
					value.Bytes[i] <<= 1
					if i+1 < len(value.Bytes) {
						value.Bytes[i] |= value.Bytes[i+1] >> 7
					}
				}
				return value
			})
			parsed, err := x509.ParseCertificate(malformed)
			if err != nil {
				t.Fatalf("unaligned BIT STRING fixture: error=%v", err)
			}
			parsedKey, ok := parsed.PublicKey.(*ecdsa.PublicKey)
			if !ok || !slices.Equal(parsed.Signature, pki.responder.Signature) || !parsedKey.Equal(pki.responder.PublicKey) {
				t.Fatal("unaligned BIT STRING fixture changed the decoded signature or key")
			}
			withCertificate.Certificates = []asn1.RawValue{{FullBytes: malformed}}
			if _, _, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, withCertificate, pki.caKey), pki.certID(t), pki.ca, now); err == nil {
				t.Fatal("accepted an unaligned BIT STRING in an unused certificate")
			}
		})
	}
	t.Run("non-certificate in unsigned certificate list", func(t *testing.T) {
		withCertificate.Certificates = []asn1.RawValue{asn1.NullRawValue}
		if _, _, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, withCertificate, pki.caKey), pki.certID(t), pki.ca, now); err == nil {
			t.Fatal("accepted a NULL certificate in an issuer-signed response")
		}
	})
	for _, test := range []struct {
		name     string
		field    int
		emptyTBS bool
	}{
		{"certificate TBS type", 0, false},
		{"certificate algorithm type", 1, false},
		{"certificate signature type", 2, false},
		{"empty certificate TBS", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			malformed := ocspTestASN1Change(t, pki.responder.Raw, []int{test.field}, func(value asn1.RawValue) asn1.RawValue {
				if test.emptyTBS {
					value.Bytes = nil
					return value
				}
				return asn1.NullRawValue
			})
			withCertificate.Certificates = []asn1.RawValue{{FullBytes: malformed}}
			if _, _, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, withCertificate, pki.caKey), pki.certID(t), pki.ca, now); err == nil {
				t.Fatal("accepted the wrong ASN.1 type in an unused certificate")
			}
		})
	}
	for _, test := range []struct {
		name string
		path []int
	}{
		{"certificate TBS extra field", []int{0}},
		{"certificate validity extra field", []int{0, 4}},
		{"certificate SPKI extra field", []int{0, 6}},
		{"certificate key algorithm extra field", []int{0, 6, 0}},
		{"certificate extensions wrapper extra field", []int{0, 7}},
		{"certificate extension extra field", []int{0, 7, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			malformed := ocspTestASN1Change(t, pki.responder.Raw, test.path, func(value asn1.RawValue) asn1.RawValue {
				value.Bytes = append(slices.Clone(value.Bytes), 5, 0)
				return value
			})
			withCertificate.Certificates = []asn1.RawValue{{FullBytes: malformed}}
			if _, _, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, withCertificate, pki.caKey), pki.certID(t), pki.ca, now); err == nil {
				t.Fatal("accepted ignored ASN.1 fields in an unused certificate")
			}
		})
	}
	additional := basic.TBSResponseData.Responses[0]
	additional.CertID.SerialNumber = big.NewInt(1000)
	status := ocspTestMarshal(t, ocspRevokedInfo{RevocationTime: now.Add(-time.Minute), Reason: 1})
	status[0] = 0xa1
	additional.CertStatus = asn1.RawValue{FullBytes: status}
	basic.TBSResponseData.Responses = append(slices.Clone(basic.TBSResponseData.Responses), additional)
	basic.TBSResponseData.Raw = nil
	basic.TBSResponseData.Raw = ocspTestMarshal(t, basic.TBSResponseData)
	if _, revoked, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, basic, pki.caKey), pki.certID(t), pki.ca, now); err != nil || revoked {
		t.Fatalf("valid unselected revoked status control: revoked=%t, error=%v", revoked, err)
	}
	for _, test := range []struct {
		name string
		path []int
		tag  int
		utc  bool
	}{
		{"revocation time type", []int{2, 1, 1, 0}, asn1.TagOctetString, false},
		{"revocation reason type", []int{2, 1, 1, 1, 0}, asn1.TagInteger, false},
		{"next update type", []int{2, 1, 3, 0}, asn1.TagInteger, false},
		{"UTC produced at", []int{1}, asn1.TagUTCTime, true},
		{"UTC this update", []int{2, 0, 2}, asn1.TagUTCTime, true},
		{"UTC next update", []int{2, 0, 3, 0}, asn1.TagUTCTime, true},
		{"UTC revocation time", []int{2, 1, 1, 0}, asn1.TagUTCTime, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			altered := basic
			altered.TBSResponseData.Raw = ocspTestASN1Change(t, basic.TBSResponseData.Raw, test.path, func(value asn1.RawValue) asn1.RawValue {
				value.Tag = test.tag
				if test.utc {
					value.Bytes = value.Bytes[2:]
				}
				return value
			})
			if _, _, err := kalkanOCSPStatus(ocspTestSignRawResponse(t, altered, pki.caKey), pki.certID(t), pki.ca, now); err == nil {
				t.Fatal("accepted malformed ASN.1 in an unselected status")
			}
		})
	}
}

func testOCSPRejectsUnexpectedEnvelopeFields(t *testing.T, raw []byte, id ocspCertID, issuer *x509.Certificate, now time.Time) {
	t.Helper()
	if _, revoked, err := kalkanOCSPStatus(raw, id, issuer, now); err != nil || revoked {
		t.Fatalf("valid envelope control: revoked=%t, error=%v", revoked, err)
	}
	appendField := func(value asn1.RawValue) asn1.RawValue {
		value.Bytes = append(slices.Clone(value.Bytes), 2, 1, 1)
		return value
	}
	for _, test := range []struct {
		name string
		path []int
	}{
		{"OCSP response", nil},
		{"response bytes explicit wrapper", []int{1}},
		{"response bytes", []int{1, 0}},
	} {
		t.Run("extra "+test.name+" field", func(t *testing.T) {
			altered := ocspTestASN1Change(t, raw, test.path, appendField)
			if _, _, err := kalkanOCSPStatus(altered, id, issuer, now); err == nil {
				t.Fatal("accepted an unexpected unsigned envelope field")
			}
		})
	}
	var response ocspResponse
	if _, err := asn1.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		path []int
	}{
		{"basic response", nil},
		{"signature algorithm", []int{1}},
		{"certificates explicit wrapper", []int{3}},
	} {
		t.Run("extra "+test.name+" field", func(t *testing.T) {
			altered := response
			altered.Bytes.Response = ocspTestASN1Change(t, response.Bytes.Response, test.path, appendField)
			if _, _, err := kalkanOCSPStatus(ocspTestMarshal(t, altered), id, issuer, now); err == nil {
				t.Fatal("accepted an unexpected unsigned basic response field")
			}
		})
	}
}

// Change a selected constructed value while preserving every other DER byte.
func ocspTestASN1Change(t *testing.T, raw []byte, path []int, change func(asn1.RawValue) asn1.RawValue) []byte {
	t.Helper()
	var value asn1.RawValue
	if rest, err := asn1.Unmarshal(raw, &value); err != nil || len(rest) != 0 || len(path) != 0 && !value.IsCompound {
		t.Fatalf("invalid test value: %v", err)
	}
	value.FullBytes = nil
	if len(path) == 0 {
		value = change(value)
	} else {
		var children []asn1.RawValue
		for remaining := value.Bytes; len(remaining) > 0; {
			var child asn1.RawValue
			var err error
			remaining, err = asn1.Unmarshal(remaining, &child)
			if err != nil {
				t.Fatal(err)
			}
			children = append(children, child)
		}
		if path[0] >= len(children) {
			t.Fatal("test field path exceeds the constructed value")
		}
		children[path[0]].FullBytes = ocspTestASN1Change(t, children[path[0]].FullBytes, path[1:], change)
		value.Bytes = nil
		for _, child := range children {
			value.Bytes = append(value.Bytes, child.FullBytes...)
		}
	}
	return ocspTestMarshal(t, value)
}

// Independent KalkanCrypt Java 0.7.5 fixtures exercise 512-bit OCSP and both
// directions of a mixed-profile certificate chain. SDK verified every signature.
// Public DER is embedded here to keep the additional tests in this existing file.
type ocspTestGOSTProfile struct {
	name, ca, leaf, response string
	bits                     int
}

func ocspTestGOSTProfiles() []ocspTestGOSTProfile {
	const (
		sdk512CA = "MIIB/DCCAWSgAwIBAgIBATAOBgoqgw4DCgEBAgMCBQAwKTEnMCUGA1UEAxMeSW5kZXBlbmRlbnQgS2Fsa2FuIEdPU1QgNTEy" +
			"IENBMCAXDTE5MDEwMTAwMDAwMFoYDzIwNTAwMTAxMDAwMDAwWjApMScwJQYDVQQDEx5JbmRlcGVuZGVudCBLYWxrYW4gR09T" +
			"VCA1MTIgQ0EwgawwIwYJKoMOAwoBAQICMBYGCiqDDgMKAQECAgEGCCqDDgMKAQMDA4GEAASBgATAG450nk/aQXbvrS7kaZBr" +
			"TnfrAsy7j7EP/ZTeEMgPi9YwhryTvrRSe1BAQRuQwsnanET/qlhVYFTKnh2yfL04/BtjiMkpLtXisjgNhjDqbnfO0aLrk04e" +
			"8g4tnzl65YqLWcLUaqvjC9+XKCTZzHHPS+W4B2d/dxZBXMmExOF0oyMwITAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE" +
			"AwIBBjAOBgoqgw4DCgEBAgMCBQADgYEABMAbjnSeT9pBdu+tLuRpkGtOd+sCzLuPsQ/9lN4QyA+L1jCGvJO+tFJ7UEBBG5DC" +
			"ydqcRP+qWFVgVMqeHbJ8vb+YaWDJER9wFdv4rUQbE7MTCbGDPNCpv/U2sqqL1omwsoRLWS+oYUZbBtp9aRQjsS3uAAVGO6zz" +
			"wqgFdZ/0+CM="
		sdk512Leaf = "MIIB+zCCAWOgAwIBAgIBAzAOBgoqgw4DCgEBAgMCBQAwKTEnMCUGA1UEAxMeSW5kZXBlbmRlbnQgS2Fsa2FuIEdPU1QgNTEy" +
			"IENBMCAXDTE5MDEwMTAwMDAwMFoYDzIwNTAwMTAxMDAwMDAwWjArMSkwJwYDVQQDEyBJbmRlcGVuZGVudCBLYWxrYW4gR09T" +
			"VCA1MTIgbGVhZjCBrDAjBgkqgw4DCgEBAgIwFgYKKoMOAwoBAQICAQYIKoMOAwoBAwMDgYQABIGAJ3f40arWEn3A+ul/sUkL" +
			"v0/Ad5pdRcpAfxtscJgrR7diY+mbfrmOwGFuaaQtdnddCabpW1D8aozxKwrb6GyGQHJ2yu729SeMyr9T5BmP3TRPCdJjj5uR" +
			"Zz0ypLZVnvhMGv3Fj4b1fyhsIGaYOquybVekUigDvkL+ZAHMIR/iMGWjIDAeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQD" +
			"AgeAMA4GCiqDDgMKAQECAwIFAAOBgQAnd/jRqtYSfcD66X+xSQu/T8B3ml1FykB/G2xwmCtHt2Jj6Zt+uY7AYW5ppC12d10J" +
			"pulbUPxqjPErCtvobIZAOnQBcbqo0uGjJXK66j6jZFbiSlN4Tf8vgyJDcaExRY/hwNJpsJtA7wggynImDAalHnM8aqXkB0JK" +
			"VOd3nQhepQ=="
		sdk512IssuerResponse = "MIIBRAoBAKCCAT0wggE5BgkrBgEFBQcwAQEEggEqMIIBJjCBj6IWBBS53VhZ+1xMc0GXUuAtwBFAemI5PhgPMjAyMDAxMDEw" +
			"MDAwMDBaMGQwYjA6MAkGBSsOAwIaBQAEFLRW/+TPfOLtfBCsz85AMcVTUpZsBBS53VhZ+1xMc0GXUuAtwBFAemI5PgIBA4AA" +
			"GA8yMDE5MTIzMTIzNTkwMFqgERgPMjA1MDAxMDEwMDAwMDBaMA4GCiqDDgMKAQECAwIFAAOBgQAoLIQrbv1egnoCLlnQ/XGW" +
			"q9oJ5iXXSSfWWdm6WFh3T2LUuXf26vvGj5x67IQZXTBdzyVpWWGC+0bcv189+fQjWHOaLJJUDLU0cys1/jJncsEP812jiid0" +
			"Z4CU4+rRj07TUkvD3nBLPxPBWzBtEY49m+nS3hnpKevAo8abXEKGxQ=="
		sdk512DelegatedResponse = "MIIDYQoBAKCCA1owggNWBgkrBgEFBQcwAQEEggNHMIIDQzCBj6IWBBTi0HbclNsrRAxxoyNktWu753L9bxgPMjAyMDAxMDEw" +
			"MDAwMDBaMGQwYjA6MAkGBSsOAwIaBQAEFLRW/+TPfOLtfBCsz85AMcVTUpZsBBS53VhZ+1xMc0GXUuAtwBFAemI5PgIBA4AA" +
			"GA8yMDE5MTIzMTIzNTkwMFqgERgPMjA1MDAxMDEwMDAwMDBaMA4GCiqDDgMKAQECAwIFAAOBgQAXn30hq10MOhUiRHVn15Rb" +
			"dAYHCko9TjaTonQeLGhJOgIwSVORiCl4x+b+kj0ObtGdsXU18E45v32+OjIqTGUIXyxd8tq+S2+BcTex//P42X8HUmW+7+Z1" +
			"VzXL5k1kxkpvUe9F/wh73ZPBD3HOnQOUQq+MMeIUi5MMUD3yVQVltaCCAhkwggIVMIICETCCAXmgAwIBAgIBBDAOBgoqgw4D" +
			"CgEBAgMCBQAwKTEnMCUGA1UEAxMeSW5kZXBlbmRlbnQgS2Fsa2FuIEdPU1QgNTEyIENBMCAXDTE5MDEwMTAwMDAwMFoYDzIw" +
			"NTAwMTAxMDAwMDAwWjAsMSowKAYDVQQDEyFJbmRlcGVuZGVudCBLYWxrYW4gT0NTUCByZXNwb25kZXIwgawwIwYJKoMOAwoB" +
			"AQICMBYGCiqDDgMKAQECAgEGCCqDDgMKAQMDA4GEAASBgKBV9K/XzZPh+QHQctCofmMXZnKBzMWDLqorLv1SUYSxAF+2Ensf" +
			"mnmiHzGPGoT8//nUTBYQ1HoyTjRLRFhOZOdCzEnsA0h9685P3I/glh62++N7CU1Ui0f9yGL7aPu6jL1JuAgZQcN2jWbHoADA" +
			"NvM729QEPkMacaNZCYIPkE1rozUwMzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcD" +
			"CTAOBgoqgw4DCgEBAgMCBQADgYEAoFX0r9fNk+H5AdBy0Kh+YxdmcoHMxYMuqisu/VJRhLEAX7YSex+aeaIfMY8ahPz/+dRM" +
			"FhDUejJONEtEWE5k5yRSIFVQhUbVBmaTJhinggnJRq72ZM+lKbMRl6H5v+LHFtF8rjLSmJVyVoWbT4RB+BiQ0M4m7SLngOqJ" +
			"UCU8i60="
		cross256CA = "MIIBhjCCAS+gAwIBAgIBATAOBgoqgw4DCgEBAgMBBQAwMDEuMCwGA1UEAxMlSW5kZXBlbmRlbnQgY3Jvc3MtcHJvZmlsZSBH" +
			"T1NUIDI1NiBDQTAgFw0xOTAxMDEwMDAwMDBaGA8yMDUwMDEwMTAwMDAwMFowMDEuMCwGA1UEAxMlSW5kZXBlbmRlbnQgY3Jv" +
			"c3MtcHJvZmlsZSBHT1NUIDI1NiBDQTBqMCMGCSqDDgMKAQECATAWBgoqgw4DCgEBAgEBBggqgw4DCgEDAgNDAARA+LWNAxpi" +
			"b4MvLZmzr0CU7V6K4b8Af4hPr0LYJxHLGEsEYuSJQyUbY5dM0KvnXFYTwz0wjpzxC5MhfvZo13VjQKMjMCEwDwYDVR0TAQH/" +
			"BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwDgYKKoMOAwoBAQIDAQUAA0EAE6G77Pmiz0CrSb1Xq+vHiFFQU+1GYEjYiBzl+vn8" +
			"YS1F3BOFrzIr4WM2G/d4TR1ubjY3wrHcltro03z9uSX3DA=="
		cross256Leaf512 = "MIIByDCCAXGgAwIBAgIBAzAOBgoqgw4DCgEBAgMBBQAwMDEuMCwGA1UEAxMlSW5kZXBlbmRlbnQgY3Jvc3MtcHJvZmlsZSBH" +
			"T1NUIDI1NiBDQTAgFw0xOTAxMDEwMDAwMDBaGA8yMDUwMDEwMTAwMDAwMFowMjEwMC4GA1UEAxMnSW5kZXBlbmRlbnQgY3Jv" +
			"c3MtcHJvZmlsZSBHT1NUIDUxMiBsZWFmMIGsMCMGCSqDDgMKAQECAjAWBgoqgw4DCgEBAgIBBggqgw4DCgEDAwOBhAAEgYBX" +
			"1qdZD94tDM7Ky1zzj0w8Ar+RKnuG4HTfkMejYfisx1d6+KL/4lWMbcJMgBSUsfPxu+bvxqg/k+BG1EsfEiPE7Bb9LLffEIvP" +
			"aLbeBZjF0GdReZGHLBAHX3uwV8CbXXjVXvHe6nh2eptnE8c6DCBXq+QfU1fP1yqsXKDuB3UFWKMgMB4wDAYDVR0TAQH/BAIw" +
			"ADAOBgNVHQ8BAf8EBAMCB4AwDgYKKoMOAwoBAQIDAQUAA0EAEDwn5xu/fOrHnQ2t0gofSM6h59f8Hh+fy/NzcqBHHinrQrTZ" +
			"9/qehJbXteRd5MijAS+RSX17rKdwWgUbQbinLw=="
		cross256Response512 = "MIIDLQoBAKCCAyYwggMiBgkrBgEFBQcwAQEEggMTMIIDDzCBj6IWBBQVaeorZyeJjrOJETJlv5XXMX0XNhgPMjAyMDAxMDEw" +
			"MDAwMDBaMGQwYjA6MAkGBSsOAwIaBQAEFAH7iIWe59+Y91/hvw5c9BMWaZnnBBS+e9yS8V2oZS+fLbRC/gtdkuAvMAIBA4AA" +
			"GA8yMDE5MTIzMTIzNTkwMFqgERgPMjA1MDAxMDEwMDAwMDBaMA4GCiqDDgMKAQECAwIFAAOBgQCFC2hNEB7BI7o7sWgW/2H7" +
			"EF0tH/qLQvuv77LSnNew64DCXi1xnKMjMOAcRW1TnDb7ED1vko+doq7WPflVnOkOsaat0/2lUeZluwSzcxz40Zylu5ukGkou" +
			"wyp0TrDfqvjXXUYk8ORo50B1G4x6jD4bGZwVEAlvl0YmDxEU2maWOqCCAeUwggHhMIIB3TCCAYagAwIBAgIBBDAOBgoqgw4D" +
			"CgEBAgMBBQAwMDEuMCwGA1UEAxMlSW5kZXBlbmRlbnQgY3Jvc3MtcHJvZmlsZSBHT1NUIDI1NiBDQTAgFw0xOTAxMDEwMDAw" +
			"MDBaGA8yMDUwMDEwMTAwMDAwMFowMjEwMC4GA1UEAxMnSW5kZXBlbmRlbnQgY3Jvc3MtcHJvZmlsZSBHT1NUIDUxMiBPQ1NQ" +
			"MIGsMCMGCSqDDgMKAQECAjAWBgoqgw4DCgEBAgIBBggqgw4DCgEDAwOBhAAEgYAErxvSCSMEZPBbeXajxeLmjznL1RfQh2B7" +
			"IINgdOg1VR/aFPH+DdYZEk7XOxH0KydharKKP066k5FyADgvty491oYPW2KTepbWUYD9E1oJ3tbJwbOjj45BU/2PQx/QS26J" +
			"SVqK2x9SPm3Gw2Ggu8SOXSQ2a+YxCAP7W1beeRDP5aM1MDMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l" +
			"BAwwCgYIKwYBBQUHAwkwDgYKKoMOAwoBAQIDAQUAA0EA8UJRNXlckd+Hxwiq1eo+58vFNrZZeULHNnB2HM2XOha9mn6lkFBT" +
			"9kFwARDnaRwpG9XCuhEQZcP921S3gmqiOg=="
		cross512CA = "MIICCjCCAXKgAwIBAgIBATAOBgoqgw4DCgEBAgMCBQAwMDEuMCwGA1UEAxMlSW5kZXBlbmRlbnQgY3Jvc3MtcHJvZmlsZSBH" +
			"T1NUIDUxMiBDQTAgFw0xOTAxMDEwMDAwMDBaGA8yMDUwMDEwMTAwMDAwMFowMDEuMCwGA1UEAxMlSW5kZXBlbmRlbnQgY3Jv" +
			"c3MtcHJvZmlsZSBHT1NUIDUxMiBDQTCBrDAjBgkqgw4DCgEBAgIwFgYKKoMOAwoBAQICAQYIKoMOAwoBAwMDgYQABIGAjsIP" +
			"NU1rtUelRLvQJ0cKdkue+q1YNkVxw9VZzRE9xF4TMo7iTjqi3gvcvp2Xeajx9dzgHMQYxfZbVwL1M8O61ov2OP+UDnUGR+YZ" +
			"imZmv8XSOHx/4eCNbFxRH2FipmT6qOQndsS6bADggNxikqypNO/x0i7WbOmhszi6X9ppdrCjIzAhMA8GA1UdEwEB/wQFMAMB" +
			"Af8wDgYDVR0PAQH/BAQDAgEGMA4GCiqDDgMKAQECAwIFAAOBgQCOwg81TWu1R6VEu9AnRwp2S576rVg2RXHD1VnNET3EXhMy" +
			"juJOOqLeC9y+nZd5qPH13OAcxBjF9ltXAvUzw7rWcI4XpQmbhTGYAWh+nC6WFoIW+jpt/kDAPjK7SeNA/enUvg9ZxF7Q02BQ" +
			"Ol9xntOpIpEX5JmDUFxuGUxGzvscZQ=="
		cross512Leaf256 = "MIIBxjCCAS6gAwIBAgIBAzAOBgoqgw4DCgEBAgMCBQAwMDEuMCwGA1UEAxMlSW5kZXBlbmRlbnQgY3Jvc3MtcHJvZmlsZSBH" +
			"T1NUIDUxMiBDQTAgFw0xOTAxMDEwMDAwMDBaGA8yMDUwMDEwMTAwMDAwMFowMjEwMC4GA1UEAxMnSW5kZXBlbmRlbnQgY3Jv" +
			"c3MtcHJvZmlsZSBHT1NUIDI1NiBsZWFmMGowIwYJKoMOAwoBAQIBMBYGCiqDDgMKAQECAQEGCCqDDgMKAQMCA0MABEA0jrLG" +
			"vSBnMuXxW1DEhC6VNF5bMPxpoWA5Mh3l+RNbhbgTAOtrj70LrPNjcYYKxJ24HC8+H6WXYNSbJ7vAiz/poyAwHjAMBgNVHRMB" +
			"Af8EAjAAMA4GA1UdDwEB/wQEAwIHgDAOBgoqgw4DCgEBAgMCBQADgYEAPrtTG6Y5llF3gT0NDDk69YxowFs2sPs/5lYFSnUW" +
			"XmF3/V2GfciEh3UNdb2dmfzTKIyEih3SjNMHt9C36bdSUDhGvStHAOrmBPN67UL65MJDihIKW1+B22lu5U5Xiid6zPBhwRAY" +
			"uyqI2JusdeXlSz/HBce1U8vEqqPU9Vc9AyE="
		cross512Response256 = "MIIC6goBAKCCAuMwggLfBgkrBgEFBQcwAQEEggLQMIICzDCBj6IWBBQ8H2obGd2QVQUbmcJE9OE73+IMjhgPMjAyMDAxMDEw" +
			"MDAwMDBaMGQwYjA6MAkGBSsOAwIaBQAEFDOt2k3NXX7PxoIxFeB7N8rUL2cCBBTGaFaQs5udEMoTu52on6dMbL1G0wIBA4AA" +
			"GA8yMDE5MTIzMTIzNTkwMFqgERgPMjA1MDAxMDEwMDAwMDBaMA4GCiqDDgMKAQECAwEFAANBAI93A1eXQngwAvU/lkdXzZAj" +
			"LONHDFx5xlSIqMQr2Yw+7y8/281wJ6CsT7WMIYXdRkCnUzi9gd0W0jovb/YNmACgggHjMIIB3zCCAdswggFDoAMCAQICAQQw" +
			"DgYKKoMOAwoBAQIDAgUAMDAxLjAsBgNVBAMTJUluZGVwZW5kZW50IGNyb3NzLXByb2ZpbGUgR09TVCA1MTIgQ0EwIBcNMTkw" +
			"MTAxMDAwMDAwWhgPMjA1MDAxMDEwMDAwMDBaMDIxMDAuBgNVBAMTJ0luZGVwZW5kZW50IGNyb3NzLXByb2ZpbGUgR09TVCAy" +
			"NTYgT0NTUDBqMCMGCSqDDgMKAQECATAWBgoqgw4DCgEBAgEBBggqgw4DCgEDAgNDAARAiLGf1hE36kMfTW0l3xhBvmOArE2o" +
			"/oOstw1jBkuveWV57FNMgxBvWZX8tAEUTLAcjPrfvfJCkErhynep/vyICaM1MDMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E" +
			"BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwkwDgYKKoMOAwoBAQIDAgUAA4GBAA3SqhOOyrj5L5aw5j4QyrpGtef1Bd13/FXK" +
			"nFBaROagzN83V8O+r6mrq3LWK1x8X6//myc+4NNeCRqxVGKXtJivz+ErNOSd3Px8EdPmckPDve09VYB8VRSWNCGmZGTe+DFP" +
			"tooqtcmACtrX3eG1W5TioSMN0Tv/JKZ6SFQo0Ij3"
	)
	return []ocspTestGOSTProfile{
		{"512 issuer", sdk512CA, sdk512Leaf, sdk512IssuerResponse, 512},
		{"512 delegate", sdk512CA, sdk512Leaf, sdk512DelegatedResponse, 512},
		{"256 issuer with 512 delegate", cross256CA, cross256Leaf512, cross256Response512, 512},
		{"512 issuer with 256 delegate", cross512CA, cross512Leaf256, cross512Response256, 256},
	}
}

func ocspTestDecodeBase64(t testing.TB, encoded string) []byte {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestOCSPGOST2015ProfileCompatibility(t *testing.T) {
	t.Parallel()
	for _, test := range ocspTestGOSTProfiles() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			issuer, err := x509.ParseCertificate(ocspTestDecodeBase64(t, test.ca))
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(ocspTestDecodeBase64(t, test.leaf))
			if err != nil {
				t.Fatal(err)
			}
			if err := checkOCSPIssuer(leaf, issuer); err != nil {
				t.Fatalf("SDK certificate signature: %v", err)
			}
			alteredLeaf := *leaf
			alteredLeaf.Signature = slices.Clone(leaf.Signature)
			alteredLeaf.Signature[0] ^= 1
			if err := checkOCSPIssuer(&alteredLeaf, issuer); err == nil {
				t.Fatal("changed certificate signature accepted")
			}
			id, err := kalkanOCSPCertID(leaf.SerialNumber, issuer)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
			response := ocspTestDecodeBase64(t, test.response)
			if at, revoked, err := kalkanOCSPStatus(response, id, issuer, now); err != nil || revoked || !at.IsZero() {
				t.Fatalf("SDK good response: revoked=%t, at=%v, error=%v", revoked, at, err)
			}
			if strings.Contains(test.name, "delegate") {
				testOCSPRejectsUnexpectedEnvelopeFields(t, response, id, issuer, now)
			}
			issuerBefore, responseBefore := slices.Clone(issuer.Raw), slices.Clone(response)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					<-start
					for range 4 {
						if at, revoked, err := kalkanOCSPStatus(response, id, issuer, now); err != nil || revoked || !at.IsZero() {
							t.Errorf("concurrent SDK good response: revoked=%t, at=%v, error=%v", revoked, at, err)
							return
						}
					}
				})
			}
			close(start)
			wg.Wait()
			if !slices.Equal(issuer.Raw, issuerBefore) || !slices.Equal(response, responseBefore) {
				t.Fatal("concurrent OCSP verification mutated shared input")
			}
			wrongIssuer := *issuer
			wrongIssuer.RawSubjectPublicKeyInfo = leaf.RawSubjectPublicKeyInfo
			if _, _, err := kalkanOCSPStatus(response, id, &wrongIssuer, now); err == nil {
				t.Fatal("response verified with a different issuer key")
			}
			var outer ocspResponse
			if _, err := asn1.Unmarshal(response, &outer); err != nil {
				t.Fatal(err)
			}
			for _, change := range []string{"signature", "profile"} {
				t.Run("changed "+change, func(t *testing.T) {
					var basic ocspBasicResponse
					if _, err := asn1.Unmarshal(outer.Bytes.Response, &basic); err != nil {
						t.Fatal(err)
					}
					if len(basic.Signature.Bytes) != test.bits/4 {
						t.Fatal("SDK fixture has the wrong signature size")
					}
					if change == "signature" {
						basic.Signature.Bytes = slices.Clone(basic.Signature.Bytes)
						basic.Signature.Bytes[0] ^= 1
					} else {
						other := 1
						if test.bits == 256 {
							other = 2
						}
						basic.SignatureAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, other}
					}
					changed := outer
					changed.Bytes.Response = ocspTestMarshal(t, basic)
					if _, _, err := kalkanOCSPStatus(ocspTestMarshal(t, changed), id, issuer, now); err == nil {
						t.Fatalf("changed response %s accepted", change)
					}
				})
			}
		})
	}
}

func FuzzOCSPStatus(f *testing.F) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	type profile struct {
		issuer *x509.Certificate
		id     ocspCertID
	}
	var profiles []profile
	add := func(issuer, leaf *x509.Certificate, response []byte) {
		id, err := kalkanOCSPCertID(leaf.SerialNumber, issuer)
		if err != nil {
			f.Fatal(err)
		}
		if _, revoked, err := kalkanOCSPStatus(response, id, issuer, now); err != nil || revoked {
			f.Fatalf("invalid OCSP fuzz control: revoked=%t, error=%v", revoked, err)
		}
		f.Add(response, uint8(len(profiles)))
		profiles = append(profiles, profile{issuer: issuer, id: id})
	}
	add(readTestCertificate(f, "testdata/ocsp/gost2015_256/gost256-ca.der"),
		readTestCertificate(f, "testdata/ocsp/gost2015_256/gost256-leaf.der"),
		readGOST256OCSPFixture(f, "gost256-ocsp-delegated-good.der"))
	for _, fixture := range ocspTestGOSTProfiles() {
		issuer, err := x509.ParseCertificate(ocspTestDecodeBase64(f, fixture.ca))
		if err != nil {
			f.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(ocspTestDecodeBase64(f, fixture.leaf))
		if err != nil {
			f.Fatal(err)
		}
		add(issuer, leaf, ocspTestDecodeBase64(f, fixture.response))
	}
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{0x30, 3, 0x0a, 1, 0}, uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, selected uint8) {
		if len(raw) > 16<<10 {
			t.Skip()
		}
		profile := profiles[int(selected)%len(profiles)]
		_, _, _ = kalkanOCSPStatus(raw, profile.id, profile.issuer, now)
	})
}
