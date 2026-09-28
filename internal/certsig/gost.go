package certsig

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/skarm/kalkan/internal/certsig/internal/gogost/gost3410"
	"github.com/skarm/kalkan/internal/certsig/internal/gogost/gost34112012512"
)

// Kazakhstan signature, public-key, and curve identifiers under the NCA RK 1.2.398.3.10.1 arc.
//
//nolint:gochecknoglobals // Immutable algorithm identifiers.
var (
	oidSignatureKazakhGost2015Digest512 = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 3, 2}
	oidPublicKeyKazakhGost2015Digest512 = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 2}
	oidKazakhGost2015Curve512           = asn1.ObjectIdentifier{1, 2, 398, 3, 10, 1, 1, 2, 2, 1}
)

// verifyKazakhGost2015 verifies 512-bit ST RK GOST R 34.10-2015 with Streebog-512.
// The key stores LE(X) || LE(Y) in an OCTET STRING inside a BIT STRING. The digest and
// signature are reversed before GoGOST verification, as checked against NCA RK certificates.
func verifyKazakhGost2015(signer *x509.Certificate, signed, signature []byte) error {
	const name = "ST RK GOST R 34.10-2015 512"

	var key struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(signer.RawSubjectPublicKeyInfo, &key); err != nil || len(rest) != 0 || key.PublicKey.BitLength%8 != 0 {
		return errors.New("certsig: malformed public key")
	}

	if !key.Algorithm.Algorithm.Equal(oidPublicKeyKazakhGost2015Digest512) {
		return fmt.Errorf("certsig: issuer public key algorithm %v cannot verify a %s signature", key.Algorithm.Algorithm, name)
	}

	// The optional hash parameter is determined by the signature algorithm.
	var parameters struct{ Curve asn1.ObjectIdentifier }
	if rest, err := asn1.Unmarshal(key.Algorithm.Parameters.FullBytes, &parameters); err != nil || len(rest) != 0 {
		return fmt.Errorf("certsig: malformed %s public key parameters", name)
	}

	if !parameters.Curve.Equal(oidKazakhGost2015Curve512) {
		return fmt.Errorf("certsig: %s curve %v: %w", name, parameters.Curve, x509.ErrUnsupportedAlgorithm)
	}

	// Kazakhstan's curve 1.2.398.3.10.1.1.2.2.1 matches TC26's 512-bit paramSetA.
	// Use a fresh value to avoid sharing mutable arithmetic state between verifiers.
	curve := gost3410.CurveIdtc26gost341012512paramSetA()

	var point []byte
	if rest, err := asn1.Unmarshal(key.PublicKey.RightAlign(), &point); err != nil || len(rest) != 0 {
		return fmt.Errorf("certsig: malformed %s public key", name)
	}

	// NewPublicKeyLE decodes coordinates but does not validate the point.
	publicKey, err := gost3410.NewPublicKeyLE(curve, point)
	if err != nil || publicKey.X.Cmp(curve.P) >= 0 || publicKey.Y.Cmp(curve.P) >= 0 || !curve.Contains(publicKey.X, publicKey.Y) {
		return fmt.Errorf("certsig: %s public key is not a curve point", name)
	}

	h := gost34112012512.New()
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
