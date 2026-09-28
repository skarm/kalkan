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

package gost34112012

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const MarshalledName = "STREEBOG"

func (h *Hash) MarshalBinary() (data []byte, err error) {
	data = make([]byte, len(MarshalledName)+1+8+2*BlockSize+len(h.buf))
	copy(data, []byte(MarshalledName))
	idx := len(MarshalledName)
	data[idx] = byte(h.size)
	idx += 1
	binary.BigEndian.PutUint64(data[idx:idx+8], h.n)
	idx += 8
	copy(data[idx:], h.hsh)
	idx += BlockSize
	copy(data[idx:], h.chk)
	idx += BlockSize
	copy(data[idx:], h.buf)
	return
}

func (h *Hash) UnmarshalBinary(data []byte) error {
	expectedLen := len(MarshalledName) + 1 + 8 + 2*BlockSize
	if len(data) < expectedLen {
		return fmt.Errorf("gogost/internal/gost34112012: len(data)=%d != %d", len(data), expectedLen)
	}
	if !bytes.HasPrefix(data, []byte(MarshalledName)) {
		return errors.New("gogost/internal/gost34112012: no hash name prefix")
	}
	idx := len(MarshalledName)
	h.size = int(data[idx])
	idx += 1
	h.n = binary.BigEndian.Uint64(data[idx : idx+8])
	idx += 8
	copy(h.hsh, data[idx:])
	idx += BlockSize
	copy(h.chk, data[idx:])
	idx += BlockSize
	h.buf = data[idx:]
	return nil
}
