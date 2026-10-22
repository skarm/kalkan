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

// Package gost34112012256 implements the GOST R 34.11-2012 256-bit hash from RFC 6986.
// Digests use big-endian byte order.
package gost34112012256

import (
	"hash"

	"github.com/skarm/kalkan/internal/certsig/internal/gogost/internal/gost34112012"
)

const (
	// BlockSize is the input block size in bytes.
	BlockSize = gost34112012.BlockSize
	// Size is the digest size in bytes.
	Size = 32
)

/*
func init() {
	crypto.RegisterHash(crypto.GOSTR34112012256, New)
}
*/

// New returns a new GOST R 34.11-2012 256-bit hash.
func New() hash.Hash {
	return gost34112012.New(32)
}
