package certsig

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/skarm/kalkan/internal/certsig/internal/gogost/gost3410"
	"github.com/skarm/kalkan/internal/certsig/internal/gogost/gost34112012256"
	"github.com/skarm/kalkan/internal/certsig/internal/gogost/gost34112012512"
)

// Kazakhstan signature, public-key, and curve identifiers under the NCA RK 1.2.398.3.10.1 arc.
//
//nolint:gochecknoglobals // Immutable algorithm identifiers.
var (
	oidSignatureKazakhGost2015Digest256 = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 1}
	oidPublicKeyKazakhGost2015Digest256 = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 1}
	oidKazakhGost2015Curve256           = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 1, 1}
	oidKazakhGost2015Digest256          = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 3, 2}
	oidSignatureKazakhGost2015Digest512 = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 2}
	oidPublicKeyKazakhGost2015Digest512 = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 2}
	oidKazakhGost2015Curve512           = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 2, 1}
	oidKazakhGost2015Digest512          = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 3, 3}
)

// verifyKazakhGost2015 verifies ST RK GOST R 34.10-2015 with the matching Streebog hash.
// The key stores LE(X) || LE(Y) in an OCTET STRING inside a BIT STRING. The digest and
// signature are reversed before GoGOST verification, as checked against NCA RK certificates.
func verifyKazakhGost2015(signer *x509.Certificate, algorithm asn1.ObjectIdentifier, signed, signature []byte) error {
	name := "ST RK GOST R 34.10-2015 512"
	publicKeyAlgorithm, curveAlgorithm := oidPublicKeyKazakhGost2015Digest512, oidKazakhGost2015Curve512
	digestAlgorithm := oidKazakhGost2015Digest512
	newCurve, newHash := gost3410.CurveIdtc26gost341012512paramSetA, gost34112012512.New

	if algorithm.Equal(oidSignatureKazakhGost2015Digest256) {
		name = "ST RK GOST R 34.10-2015 256"
		publicKeyAlgorithm, curveAlgorithm = oidPublicKeyKazakhGost2015Digest256, oidKazakhGost2015Curve256
		digestAlgorithm = oidKazakhGost2015Digest256
		newCurve, newHash = gost3410.CurveIdtc26gost341012256paramSetA, gost34112012256.New
	}

	var key struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(signer.RawSubjectPublicKeyInfo, &key); err != nil || len(rest) != 0 || key.PublicKey.BitLength%8 != 0 ||
		!matchesASN1Encoding(signer.RawSubjectPublicKeyInfo, key) {
		return errors.New("certsig: malformed public key")
	}

	if !key.Algorithm.Algorithm.Equal(publicKeyAlgorithm) {
		return fmt.Errorf("certsig: issuer public key algorithm %v cannot verify a %s signature", key.Algorithm.Algorithm, name)
	}

	curveOID, digestOID, err := kazakhGost2015Parameters(key.Algorithm.Parameters.FullBytes)
	if err != nil {
		return fmt.Errorf("certsig: malformed %s public key parameters: %w", name, err)
	}

	if !curveOID.Equal(curveAlgorithm) {
		return fmt.Errorf("certsig: %s curve %v: %w", name, curveOID, x509.ErrUnsupportedAlgorithm)
	}

	// The signature algorithm fixes the digest. If the key also declares a
	// digest parameter, it must agree with that algorithm.
	if len(digestOID) != 0 && !digestOID.Equal(digestAlgorithm) {
		return fmt.Errorf("certsig: %s digest %v: %w", name, digestOID, x509.ErrUnsupportedAlgorithm)
	}

	// Kazakhstan's 256-bit and 512-bit curves match the respective TC26 paramSetA.
	// Use a fresh value to avoid sharing mutable arithmetic state between verifiers.
	curve := newCurve()

	var point []byte
	if rest, err := asn1.Unmarshal(key.PublicKey.RightAlign(), &point); err != nil || len(rest) != 0 {
		return fmt.Errorf("certsig: malformed %s public key", name)
	}

	// NewPublicKeyLE only decodes coordinates. Check bounds and subgroup membership;
	// the 256-bit curve has cofactor 4, so an on-curve check alone is insufficient.
	publicKey, err := gost3410.NewPublicKeyLE(curve, point)
	if err != nil || !curve.IsInSubgroup(publicKey.X, publicKey.Y) {
		return fmt.Errorf("certsig: invalid %s public key", name)
	}

	h := newHash()
	h.Write(signed)

	valid, err := (gost3410.PublicKeyReverseDigestAndSignature{Pub: publicKey}).VerifyDigest(h.Sum(nil), signature)
	if err != nil {
		return fmt.Errorf("certsig: %s verification failure: %w", name, err)
	}

	if !valid {
		return fmt.Errorf("certsig: %s verification failure", name)
	}

	return nil
}

// kazakhGost2015Parameters reads a curve OID and an optional digest OID, rejecting
// extra or malformed fields rather than ignoring trailing sequence contents.
func kazakhGost2015Parameters(encoded []byte) (asn1.ObjectIdentifier, asn1.ObjectIdentifier, error) {
	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(encoded, &sequence); err != nil || len(rest) != 0 ||
		sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return nil, nil, errors.New("expected a parameter sequence")
	}

	var curve, digest asn1.ObjectIdentifier

	rest, err := asn1.Unmarshal(sequence.Bytes, &curve)
	if err != nil {
		return nil, nil, err
	}

	if len(rest) != 0 {
		if rest, err = asn1.Unmarshal(rest, &digest); err != nil || len(rest) != 0 {
			return nil, nil, errors.New("expected a single digest OID")
		}
	}

	return curve, digest, nil
}
