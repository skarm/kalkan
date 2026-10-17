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
	"errors"
	"math/big"
)

var (
	errInfinitePoint = errors.New("gogost/gost3410: point at infinity")

	zero    = big.NewInt(0)
	bigInt1 = big.NewInt(1)
	bigInt2 = big.NewInt(2)
	bigInt3 = big.NewInt(3)
	bigInt4 = big.NewInt(4)
)

type Curve struct {
	P *big.Int // Characteristic of the underlying prime field
	Q *big.Int // Elliptic curve subgroup order

	Co *big.Int // Cofactor

	// Equation coefficients of the elliptic curve in canonical form
	A *big.Int
	B *big.Int

	// Equation coefficients of the elliptic curve in twisted Edwards form
	E *big.Int
	D *big.Int

	// Basic point X and Y coordinates
	X *big.Int
	Y *big.Int

	// Cached s/t parameters for Edwards curve points conversion
	edS *big.Int
	edT *big.Int

	Name string // Just simple identifier
}

// NewCurve copies its parameters. A curve can be read concurrently as long as
// callers do not mutate its exported fields.
func NewCurve(p, q, a, b, x, y, e, d, co *big.Int) (*Curve, error) {
	c := Curve{
		Name: "unknown",
		P:    new(big.Int).Set(p),
		Q:    new(big.Int).Set(q),
		A:    new(big.Int).Set(a),
		B:    new(big.Int).Set(b),
		X:    new(big.Int).Set(x),
		Y:    new(big.Int).Set(y),
	}

	if !c.Contains(c.X, c.Y) {
		return nil, errors.New("gogost/gost3410: invalid curve parameters")
	}

	if e != nil && d != nil {
		c.E = new(big.Int).Set(e)
		c.D = new(big.Int).Set(d)
	}

	if co == nil {
		c.Co = new(big.Int).Set(bigInt1)
	} else {
		c.Co = new(big.Int).Set(co)
	}

	return &c, nil
}

// Is point on curve?
func (c *Curve) Contains(x, y *big.Int) bool {
	r1 := big.NewInt(0)
	r2 := big.NewInt(0)
	r1.Mul(y, y)
	r1.Mod(r1, c.P)
	r2.Mul(x, x)
	r2.Add(r2, c.A)
	r2.Mul(r2, x)
	r2.Add(r2, c.B)
	r2.Mod(r2, c.P)
	c.pos(r2)

	return r1.Cmp(r2) == 0
}

// IsInSubgroup checks canonical coordinates and membership in the subgroup of order Q.
func (c *Curve) IsInSubgroup(x, y *big.Int) bool {
	if x == nil || y == nil || x.Sign() < 0 || y.Sign() < 0 ||
		x.Cmp(c.P) >= 0 || y.Cmp(c.P) >= 0 || !c.Contains(x, y) {
		return false
	}

	if c.Co.Cmp(bigInt1) == 0 {
		return true
	}

	_, _, err := c.Exp(c.Q, x, y)

	return errors.Is(err, errInfinitePoint)
}

// PointSize get the size of the point's coordinate in bytes.
// 32 for 256-bit curves, 64 for 512-bit ones.
func (c *Curve) PointSize() int {
	return pointSize(c.P)
}

func (c *Curve) pos(v *big.Int) {
	if v.Cmp(zero) < 0 {
		v.Add(v, c.P)
	}
}

// add writes a finite sum to p1 and returns false if the sum is infinity.
func (c *Curve) add(p1x, p1y, p2x, p2y *big.Int) bool {
	var t, tx, ty big.Int
	if p1x.Cmp(p2x) == 0 {
		if p1y.Cmp(p2y) != 0 || p1y.Sign() == 0 {
			return false
		}
		// double
		t.Mul(p1x, p1x)
		t.Mul(&t, bigInt3)
		t.Add(&t, c.A)
		tx.Mul(bigInt2, p1y)
		if tx.ModInverse(&tx, c.P) == nil {
			return false
		}
		t.Mul(&t, &tx)
		t.Mod(&t, c.P)
	} else {
		tx.Sub(p2x, p1x)
		tx.Mod(&tx, c.P)
		c.pos(&tx)
		ty.Sub(p2y, p1y)
		ty.Mod(&ty, c.P)
		c.pos(&ty)
		if t.ModInverse(&tx, c.P) == nil {
			return false
		}
		t.Mul(&t, &ty)
		t.Mod(&t, c.P)
	}

	tx.Mul(&t, &t)
	tx.Sub(&tx, p1x)
	tx.Sub(&tx, p2x)
	tx.Mod(&tx, c.P)
	c.pos(&tx)
	ty.Sub(p1x, &tx)
	ty.Mul(&ty, &t)
	ty.Sub(&ty, p1y)
	ty.Mod(&ty, c.P)
	c.pos(&ty)
	p1x.Set(&tx)
	p1y.Set(&ty)

	return true
}

func (c *Curve) Exp(degree, xS, yS *big.Int) (*big.Int, *big.Int, error) {
	if degree.Sign() <= 0 {
		return nil, nil, errors.New("gogost/gost3410: nonpositive degree value")
	}

	tx, ty := new(big.Int), new(big.Int)
	infinity := true

	for i := degree.BitLen() - 1; i >= 0; i-- {
		if !infinity {
			infinity = !c.add(tx, ty, tx, ty)
		}

		if degree.Bit(i) == 1 {
			if infinity {
				tx.Set(xS)
				ty.Set(yS)
				infinity = false
			} else {
				infinity = !c.add(tx, ty, xS, yS)
			}
		}
	}

	if infinity {
		return nil, nil, errInfinitePoint
	}

	return tx, ty, nil
}

func (our *Curve) Equal(their *Curve) bool {
	return our.P.Cmp(their.P) == 0 &&
		our.Q.Cmp(their.Q) == 0 &&
		our.A.Cmp(their.A) == 0 &&
		our.B.Cmp(their.B) == 0 &&
		our.X.Cmp(their.X) == 0 &&
		our.Y.Cmp(their.Y) == 0 &&
		optionalIntEqual(our.E, their.E) &&
		optionalIntEqual(our.D, their.D) &&
		our.Co.Cmp(their.Co) == 0
}

func optionalIntEqual(our, their *big.Int) bool {
	if our == nil || their == nil {
		return our == their
	}

	return our.Cmp(their) == 0
}

func (c *Curve) String() string {
	return c.Name
}
