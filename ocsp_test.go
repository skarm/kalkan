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
	"encoding/pem"
	"math/big"
	"os"
	"slices"
	"strings"
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
	signed := ocspTestMarshal(t, basic.TBSResponseData)
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

func readTestCertificate(t *testing.T, path string) *x509.Certificate {
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
