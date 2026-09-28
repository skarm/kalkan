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

// GOST R 34.11-2012 hash function.
// RFC 6986.
package gost34112012

import (
	"crypto/subtle"
	"encoding/binary"
)

const BlockSize = 64

type Hash struct {
	buf  []byte
	hsh  []byte
	chk  []byte
	n    uint64
	size int
}

// Create new hash object with specified size digest size.
func New(size int) *Hash {
	if size != 32 && size != 64 {
		panic("size must be either 32 or 64")
	}
	h := Hash{
		size: size,
		hsh:  make([]byte, BlockSize),
		chk:  make([]byte, BlockSize),
	}
	h.Reset()
	return &h
}

func (h *Hash) Reset() {
	h.n = 0
	h.buf = nil
	clear(h.chk)
	for i := range BlockSize {
		if h.size == 32 {
			h.hsh[i] = 1
		} else {
			h.hsh[i] = 0
		}
	}
}

func (h *Hash) BlockSize() int {
	return BlockSize
}

func (h *Hash) Size() int {
	return h.size
}

func add512bit(out, chk, data []byte) []byte {
	var ss uint16
	for i := range BlockSize {
		ss = uint16(chk[i]) + uint16(data[i]) + (ss >> 8)
		out[i] = byte(0xFF & ss)
	}
	return out
}

func lps(out, data []byte) {
	var res [BlockSize]byte
	for i := range 8 {
		binary.LittleEndian.PutUint64(res[i*8:i*8+8],
			precalc[0][data[8*0+i]]^
				precalc[1][data[8*1+i]]^
				precalc[2][data[8*2+i]]^
				precalc[3][data[8*3+i]]^
				precalc[4][data[8*4+i]]^
				precalc[5][data[8*5+i]]^
				precalc[6][data[8*6+i]]^
				precalc[7][data[8*7+i]])
	}
	copy(out, res[:])
}

func (h *Hash) g(dst []byte, n uint64, hsh, data []byte) {
	var out [BlockSize]byte
	copy(out[:], hsh)
	out[0] ^= byte((n >> 0) & 0xFF)
	out[1] ^= byte((n >> 8) & 0xFF)
	out[2] ^= byte((n >> 16) & 0xFF)
	out[3] ^= byte((n >> 24) & 0xFF)
	out[4] ^= byte((n >> 32) & 0xFF)
	out[5] ^= byte((n >> 40) & 0xFF)
	out[6] ^= byte((n >> 48) & 0xFF)
	out[7] ^= byte((n >> 56) & 0xFF)
	lps(out[:], out[:])
	e(out[:], out[:], data)
	subtle.XORBytes(out[:], out[:], hsh)
	subtle.XORBytes(out[:], out[:], data)
	copy(dst, out[:])
}

func e(out, k, msg []byte) {
	var msgBuf, kBuf, xorBuf [BlockSize]byte
	for i := range 12 {
		subtle.XORBytes(xorBuf[:], k, msg)
		lps(msgBuf[:], xorBuf[:])
		msg = msgBuf[:]
		subtle.XORBytes(xorBuf[:], k, c[i][:])
		lps(kBuf[:], xorBuf[:])
		k = kBuf[:]
	}
	subtle.XORBytes(out, k, msg)
}

func (h *Hash) Write(data []byte) (int, error) {
	h.buf = append(h.buf, data...)
	var addBuf, tmp [BlockSize]byte
	for len(h.buf) >= BlockSize {
		copy(tmp[:], h.buf[:BlockSize])
		h.g(h.hsh, h.n, h.hsh, tmp[:])
		copy(h.chk, add512bit(addBuf[:], h.chk, tmp[:]))
		h.n += BlockSize * 8
		h.buf = h.buf[BlockSize:]
	}
	return len(data), nil
}

func (h *Hash) Sum(in []byte) []byte {
	var buf, hsh, tmp, addBuf [BlockSize]byte
	copy(buf[:], h.buf)
	buf[len(h.buf)] = 1
	h.g(hsh[:], h.n, h.hsh, buf[:])
	binary.LittleEndian.PutUint64(tmp[:], h.n+uint64(len(h.buf))*8)
	h.g(hsh[:], 0, hsh[:], tmp[:])
	h.g(hsh[:], 0, hsh[:], add512bit(addBuf[:], h.chk, buf[:]))
	if h.size == 32 {
		return append(in, hsh[BlockSize/2:]...)
	}
	return append(in, hsh[:]...)
}
