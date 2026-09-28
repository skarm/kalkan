package kalkan

import (
	"crypto/sha1" // #nosec G505 -- SHA-1 OCSP CertID is understood by all responders (RFC 5019, 2.1.1); this is an identifier, not a signature.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/skarm/kalkan/internal/certsig"
)

// kalkanOCSPMaxResponseBytes limits the OCSP response body: the certificate status and the
// responder certificate normally occupy only a few kilobytes.
const kalkanOCSPMaxResponseBytes = 1 << 20

// kalkanOCSPMaxAge is the lifetime of a response without nextUpdate. Such a responder indicates
// that fresh status is always available (RFC 6960, 4.2.2.1); a response older than an hour is
// considered a replay rather than a response to this request.
const kalkanOCSPMaxAge = time.Hour

// kalkanRevocationClockSkew is the allowed lead of an OCSP response's thisUpdate over the
// client's clock.
const kalkanRevocationClockSkew = 5 * time.Minute

//nolint:gochecknoglobals // Immutable SHA-1 (RFC 3279) and id-pkix-ocsp-basic (RFC 6960, 4.2.1) identifiers.
var (
	oidSHA1      = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
)

// ocspCertID is CertID (RFC 6960, 4.1.1): issuer name and key hashes plus the certificate serial number.
type ocspCertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// matches reports whether the response's CertID identifies the same certificate. Responders
// encode hash algorithm parameters either as NULL or omit them, so only the algorithm OID is compared.
func (id ocspCertID) matches(other ocspCertID) bool {
	return other.HashAlgorithm.Algorithm.Equal(id.HashAlgorithm.Algorithm) && slices.Equal(other.IssuerNameHash, id.IssuerNameHash) &&
		slices.Equal(other.IssuerKeyHash, id.IssuerKeyHash) && id.SerialNumber != nil && other.SerialNumber != nil && other.SerialNumber.Cmp(id.SerialNumber) == 0
}

// ocspRequest is an unsigned OCSPRequest with one request and no extensions (RFC 6960, 4.1.1).
type ocspRequest struct {
	TBSRequest struct {
		RequestList []struct{ CertID ocspCertID }
	}
}

// ocspResponse — OCSPResponse (RFC 6960, 4.2.1).
type ocspResponse struct {
	Status asn1.Enumerated
	Bytes  struct {
		Type     asn1.ObjectIdentifier
		Response []byte
	} `asn1:"explicit,tag:0,optional"`
}

// ocspBasicResponse — BasicOCSPResponse (RFC 6960, 4.2.1).
type ocspBasicResponse struct {
	TBSResponseData    ocspResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// ocspResponseData is ResponseData; Raw contains the entire signed portion.
type ocspResponseData struct {
	Raw         asn1.RawContent
	Version     int `asn1:"optional,default:0,explicit,tag:0"`
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []ocspSingleResponse
	Extensions  []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

// ocspSingleResponse is SingleResponse; certStatus is one of good, revoked, or unknown.
type ocspSingleResponse struct {
	CertID     ocspCertID
	CertStatus asn1.RawValue
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"optional,generalized,explicit,tag:0"`
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

// ocspRevokedInfo is RevokedInfo: when and why the certificate was revoked.
type ocspRevokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"optional,explicit,tag:0"`
}

// kalkanOCSPCertID builds the CertID for serial, issued by issuer: SHA-1 of the issuer's name
// and public key value, excluding the tag, length, and unused-bit count (RFC 6960, 4.1.1).
// The name is issuer's subject: chain traversal matched it byte for byte to the certificate's issuer name.
func kalkanOCSPCertID(serial *big.Int, issuer *x509.Certificate) (ocspCertID, error) {
	keyHash, err := kalkanOCSPPublicKeyHash(issuer)
	if err != nil {
		return ocspCertID{}, errors.New("the issuer public key is malformed")
	}

	name := sha1.Sum(issuer.RawSubject) // #nosec G401 -- OCSP CertID, not a signature.

	return ocspCertID{
		HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: oidSHA1, Parameters: asn1.NullRawValue},
		IssuerNameHash: name[:], IssuerKeyHash: keyHash, SerialNumber: serial,
	}, nil
}

// kalkanOCSPPublicKeyHash computes the SHA-1 identifier shared by CertID and ResponderID
// byKey, excluding the subjectPublicKey tag, length, and unused-bit count (RFC 6960, Appendix B.1).
func kalkanOCSPPublicKeyHash(certificate *x509.Certificate) ([]byte, error) {
	var key struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	if rest, err := asn1.Unmarshal(certificate.RawSubjectPublicKeyInfo, &key); err != nil || len(rest) != 0 {
		return nil, errors.New("the certificate public key is malformed")
	}

	keyHash := sha1.Sum(key.PublicKey.RightAlign()) // #nosec G401 -- OCSP key identifier, not a signature.

	return keyHash[:], nil
}

// kalkanOCSPRequest encodes an OCSP request for certificate id.
func kalkanOCSPRequest(id ocspCertID) ([]byte, error) {
	var request ocspRequest

	request.TBSRequest.RequestList = []struct{ CertID ocspCertID }{{CertID: id}}

	return asn1.Marshal(request)
}

// kalkanOCSPStatus reads an OCSP response for certificate id, issued by issuer, at now.
// A true result and revocation time mean revoked; false without an error means not revoked.
// The response must be signed by issuer or its delegated OCSP responder (kalkanOCSPSigner).
// Responder refusal (responseStatus), a different certificate, unknown status, an unsupported
// critical extension (RFC 6960, 4.4), a future response, or a stale response cannot establish status.
// A response is stale after nextUpdate, or after kalkanOCSPMaxAge when nextUpdate is absent.
func kalkanOCSPStatus(raw []byte, id ocspCertID, issuer *x509.Certificate, now time.Time) (time.Time, bool, error) {
	if len(raw) > kalkanOCSPMaxResponseBytes {
		return time.Time{}, false, errors.New("the OCSP response exceeds the size limit")
	}

	var response ocspResponse
	if rest, err := asn1.Unmarshal(raw, &response); err != nil || len(rest) != 0 {
		return time.Time{}, false, errors.New("the answer is not an OCSP response")
	}

	if response.Status != 0 {
		return time.Time{}, false, fmt.Errorf("the responder refused the request with responseStatus %d", response.Status)
	}

	if !response.Bytes.Type.Equal(oidOCSPBasic) {
		return time.Time{}, false, fmt.Errorf("the response type %v is not id-pkix-ocsp-basic", response.Bytes.Type)
	}

	var basic ocspBasicResponse
	if rest, err := asn1.Unmarshal(response.Bytes.Response, &basic); err != nil || len(rest) != 0 {
		return time.Time{}, false, errors.New("the basic OCSP response is malformed")
	}

	if basic.TBSResponseData.Version != 0 {
		return time.Time{}, false, errors.New("the OCSP response version is unsupported")
	}

	if basic.Signature.BitLength%8 != 0 {
		return time.Time{}, false, errors.New("the OCSP response signature is malformed")
	}

	if err := kalkanOCSPSigner(basic, issuer, now); err != nil {
		return time.Time{}, false, err
	}

	if kalkanCriticalExtension(basic.TBSResponseData.Extensions) {
		return time.Time{}, false, errors.New("the response carries an unsupported critical extension")
	}

	if basic.TBSResponseData.ProducedAt.After(now.Add(kalkanRevocationClockSkew)) {
		return time.Time{}, false, errors.New("the OCSP response was produced in the future")
	}

	index := -1

	for i, single := range basic.TBSResponseData.Responses {
		if id.matches(single.CertID) {
			if index >= 0 {
				return time.Time{}, false, errors.New("the response has multiple statuses of the certificate")
			}

			index = i
		}
	}

	if index < 0 {
		return time.Time{}, false, errors.New("the response has no status of the certificate")
	}

	return kalkanOCSPSingleStatus(basic.TBSResponseData.Responses[index], now)
}

func kalkanOCSPSingleStatus(single ocspSingleResponse, now time.Time) (time.Time, bool, error) {
	switch expires := single.NextUpdate; {
	case kalkanCriticalExtension(single.Extensions):
		return time.Time{}, false, errors.New("the certificate status carries an unsupported critical extension")
	case single.ThisUpdate.After(now.Add(kalkanRevocationClockSkew)):
		return time.Time{}, false, errors.New("the certificate status is issued in the future")
	case !expires.IsZero() && !expires.After(single.ThisUpdate):
		return time.Time{}, false, errors.New("the certificate status nextUpdate must follow thisUpdate")
	case expires.IsZero() && now.Sub(single.ThisUpdate) > kalkanOCSPMaxAge, !expires.IsZero() && !expires.After(now):
		return time.Time{}, false, errors.New("the certificate status is stale")
	}

	status := single.CertStatus
	if status.Class == asn1.ClassContextSpecific {
		switch status.Tag {
		case 0, 2: // good and unknown are implicitly tagged NULL values.
			if !status.IsCompound && len(status.Bytes) == 0 {
				if status.Tag == 0 {
					return time.Time{}, false, nil
				}

				return time.Time{}, false, errors.New("the responder does not know the certificate")
			}
		case 1:
			var revoked ocspRevokedInfo
			if rest, err := asn1.UnmarshalWithParams(status.FullBytes, &revoked, "tag:1"); err == nil && len(rest) == 0 && !revoked.RevocationTime.IsZero() {
				return revoked.RevocationTime, true, nil
			}
		}
	}

	return time.Time{}, false, errors.New("the certificate status is malformed")
}

// kalkanOCSPSigner verifies the response signature using issuer's key or a delegated responder's
// key. The responder certificate must be embedded in the response, signed by issuer, valid at now,
// and carry id-kp-OCSPSigning (RFC 6960, 4.2.2.2). Local policy does not separately check responder
// certificate revocation, even without id-pkix-ocsp-nocheck; no recursive network checks are made.
func kalkanOCSPSigner(basic ocspBasicResponse, issuer *x509.Certificate, now time.Time) error {
	signed, signature := []byte(basic.TBSResponseData.Raw), basic.Signature.RightAlign()

	issuerErr := errors.New("the responder ID does not identify the issuer")
	if kalkanOCSPResponderMatches(basic.TBSResponseData.ResponderID, issuer) {
		issuerErr = certsig.CheckSignature(issuer, basic.SignatureAlgorithm, signed, signature)
		if issuerErr == nil {
			return nil
		}
	}

	for _, raw := range basic.Certificates {
		responder, err := parseOCSPDERCertificate(raw.FullBytes)
		if err != nil || !kalkanCertificateValidAt(responder, now) || !slices.Contains(responder.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) ||
			len(responder.UnhandledCriticalExtensions) != 0 || !kalkanOCSPDigitalSignatureAllowed(responder) ||
			!slices.Equal(responder.RawIssuer, issuer.RawSubject) || !kalkanOCSPResponderMatches(basic.TBSResponseData.ResponderID, responder) ||
			certsig.CheckCertificateSignature(responder, issuer) != nil {
			continue
		}

		if certsig.CheckSignature(responder, basic.SignatureAlgorithm, signed, signature) == nil {
			return nil
		}
	}

	return fmt.Errorf("the response is signed neither by the issuer nor by its OCSP responder: %w", issuerErr)
}

// kalkanOCSPResponderMatches binds ResponderID to the certificate whose key verifies the response.
// Both alternatives are explicitly tagged: byName [1] Name and byKey [2] OCTET STRING.
func kalkanOCSPResponderMatches(id asn1.RawValue, signer *x509.Certificate) bool {
	if signer == nil || id.Class != asn1.ClassContextSpecific || !id.IsCompound {
		return false
	}

	switch id.Tag {
	case 1:
		return slices.Equal(id.Bytes, signer.RawSubject)
	case 2:
		var hash []byte
		if rest, err := asn1.Unmarshal(id.Bytes, &hash); err != nil || len(rest) != 0 || len(hash) != sha1.Size {
			return false
		}

		keyHash, err := kalkanOCSPPublicKeyHash(signer)

		return err == nil && slices.Equal(hash, keyHash)
	default:
		return false
	}
}

func kalkanOCSPDigitalSignatureAllowed(signer *x509.Certificate) bool {
	// KeyUsage == 0 also occurs for an explicitly empty extension; only omission means unrestricted.
	for _, extension := range signer.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
			return signer.KeyUsage&x509.KeyUsageDigitalSignature != 0
		}
	}

	return true
}

func kalkanCertificateValidAt(certificate *x509.Certificate, now time.Time) bool {
	return !now.Before(certificate.NotBefore) && !now.After(certificate.NotAfter)
}

// kalkanCriticalExtension reports whether any extension is critical: this code does not
// interpret any OCSP response extensions.
func kalkanCriticalExtension(extensions []pkix.Extension) bool {
	return slices.ContainsFunc(extensions, func(extension pkix.Extension) bool { return extension.Critical })
}
