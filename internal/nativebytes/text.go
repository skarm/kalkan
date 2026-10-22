// Package nativebytes interprets byte buffers shared by the native SDK layers.
package nativebytes

import "bytes"

// BeforeNUL returns a borrowed view before the first NUL byte.
// Its capacity equals its length.
// Use it only for native C-string outputs.
// Binary data can contain meaningful zero bytes.
// Bytes after a text terminator can contain unspecified SDK padding.
func BeforeNUL(value []byte) []byte {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		return value[:index:index]
	}

	return value[:len(value):len(value)]
}
