// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2026 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package gost3410

import (
	"crypto"
	"fmt"
	"math/big"
)

// PublicKey contains a public point on an elliptic curve.
type PublicKey struct {
	// C is the public key's curve.
	C *Curve
	// X and Y are the public point's coordinates on C.
	X, Y *big.Int
}

// NewPublicKeyLE returns a public key on c from raw in LE(X)||LE(Y) format.
// raw must contain 2*c.PointSize() bytes.
// The function checks the length but does not validate curve or subgroup membership.
func NewPublicKeyLE(c *Curve, raw []byte) (*PublicKey, error) {
	pointSize := c.PointSize()
	key := make([]byte, 2*pointSize)
	if len(raw) != len(key) {
		return nil, fmt.Errorf("gogost/gost3410: len(key) != %d", len(key))
	}

	for i := range len(key) {
		key[i] = raw[len(raw)-i-1]
	}

	return &PublicKey{
		c,
		bytes2big(key[pointSize : 2*pointSize]),
		bytes2big(key[:pointSize]),
	}, nil
}

// NewPublicKeyBE returns a public key on c from raw in BE(X)||BE(Y) format.
// raw must contain 2*c.PointSize() bytes.
// The function checks the length but does not validate curve or subgroup membership.
func NewPublicKeyBE(c *Curve, raw []byte) (*PublicKey, error) {
	pointSize := c.PointSize()
	if len(raw) != 2*pointSize {
		return nil, fmt.Errorf("gogost/gost3410: len(key) != %d", 2*pointSize)
	}

	return &PublicKey{
		c,
		bytes2big(raw[:pointSize]),
		bytes2big(raw[pointSize:]),
	}, nil
}

// NewPublicKey calls [NewPublicKeyLE] with c and raw.
func NewPublicKey(c *Curve, raw []byte) (*PublicKey, error) {
	return NewPublicKeyLE(c, raw)
}

// RawLE returns pk in LE(X)||LE(Y) format.
// Each coordinate occupies pk.C.PointSize() bytes.
func (pk *PublicKey) RawLE() []byte {
	pointSize := pk.C.PointSize()
	raw := append(
		pad(pk.Y.Bytes(), pointSize),
		pad(pk.X.Bytes(), pointSize)...,
	)
	reverse(raw)

	return raw
}

// RawBE returns pk in BE(X)||BE(Y) format.
// Each coordinate occupies pk.C.PointSize() bytes.
func (pk *PublicKey) RawBE() []byte {
	pointSize := pk.C.PointSize()
	return append(
		pad(pk.X.Bytes(), pointSize),
		pad(pk.Y.Bytes(), pointSize)...,
	)
}

// Raw returns the same encoding as [PublicKey.RawLE].
func (pk *PublicKey) Raw() []byte {
	return pk.RawLE()
}

// VerifyDigest reports whether signature verifies digest with pk.
// signature must contain big-endian s followed by big-endian r.
// An invalid signature length returns an error.
func (pk *PublicKey) VerifyDigest(digest, signature []byte) (bool, error) {
	pointSize := pk.C.PointSize()
	if len(signature) != 2*pointSize {
		return false, fmt.Errorf("gogost/gost3410: len(signature)=%d != %d", len(signature), 2*pointSize)
	}

	s := bytes2big(signature[:pointSize])
	r := bytes2big(signature[pointSize:])

	if r.Cmp(zero) <= 0 ||
		r.Cmp(pk.C.Q) >= 0 ||
		s.Cmp(zero) <= 0 ||
		s.Cmp(pk.C.Q) >= 0 {
		return false, nil
	}

	e := bytes2big(digest)
	e.Mod(e, pk.C.Q)

	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}

	v := big.NewInt(0)
	v.ModInverse(e, pk.C.Q)
	z1 := big.NewInt(0)
	z2 := big.NewInt(0)
	z1.Mul(s, v)
	z1.Mod(z1, pk.C.Q)
	z2.Mul(r, v)
	z2.Mod(z2, pk.C.Q)
	z2.Sub(pk.C.Q, z2)

	p1x, p1y, err := pk.C.Exp(z1, pk.C.X, pk.C.Y)
	if err != nil {
		return false, err
	}

	q1x, q1y, err := pk.C.Exp(z2, pk.X, pk.Y)
	if err != nil {
		return false, err
	}
	// Equal points require doubling.
	// Opposite points sum to infinity and cannot verify a signature.
	// The slope for distinct points has no inverse when their x coordinates match.
	if !pk.C.add(p1x, p1y, q1x, q1y) {
		return false, nil
	}
	p1x.Mod(p1x, pk.C.Q)
	return p1x.Cmp(r) == 0, nil
}

// Equal reports whether theirKey is a *PublicKey with the same coordinates and curve parameters as pk.
func (pk *PublicKey) Equal(theirKey crypto.PublicKey) bool {
	their, ok := theirKey.(*PublicKey)
	if !ok {
		return false
	}

	return pk.X.Cmp(their.X) == 0 && pk.Y.Cmp(their.Y) == 0 && pk.C.Equal(their.C)
}

// PublicKeyReverseDigest reverses digest bytes before verification with Pub.
type PublicKeyReverseDigest struct {
	// Pub is the public key that verifies the reversed digest.
	Pub *PublicKey
}

// VerifyDigest reports whether signature verifies a reversed copy of digest with pub.Pub.
// It preserves both input slices.
func (pub PublicKeyReverseDigest) VerifyDigest(digest, signature []byte) (bool, error) {
	dgst := make([]byte, len(digest))
	for i := range len(digest) {
		dgst[i] = digest[len(digest)-i-1]
	}

	return pub.Pub.VerifyDigest(dgst, signature)
}

// Equal reports whether theirKey matches pub.Pub under [PublicKey.Equal].
func (pub PublicKeyReverseDigest) Equal(theirKey crypto.PublicKey) bool {
	return pub.Pub.Equal(theirKey)
}

// PublicKeyReverseDigestAndSignature reverses digest and signature bytes before verification with Pub.
type PublicKeyReverseDigestAndSignature struct {
	// Pub is the public key that verifies the reversed inputs.
	Pub *PublicKey
}

// VerifyDigest reports whether reversed copies of digest and signature verify with pub.Pub.
// It preserves both input slices.
func (pub PublicKeyReverseDigestAndSignature) VerifyDigest(digest, signature []byte) (bool, error) {
	dgst := make([]byte, len(digest))

	for i := range len(digest) {
		dgst[i] = digest[len(digest)-i-1]
	}

	sign := make([]byte, len(signature))

	for i := range len(signature) {
		sign[i] = signature[len(signature)-i-1]
	}

	return pub.Pub.VerifyDigest(dgst, sign)
}

// Equal reports whether theirKey matches pub.Pub under [PublicKey.Equal].
func (pub PublicKeyReverseDigestAndSignature) Equal(theirKey crypto.PublicKey) bool {
	return pub.Pub.Equal(theirKey)
}
