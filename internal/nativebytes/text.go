// Package nativebytes interprets byte buffers shared by the native SDK layers.
package nativebytes

import "bytes"

// BeforeNUL returns a borrowed, capacity-limited view before the first NUL byte.
// Use it only for native C-string outputs; binary data may contain meaningful
// zero bytes. Bytes after a textual terminator may be unspecified SDK padding.
func BeforeNUL(value []byte) []byte {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		return value[:index:index]
	}

	return value[:len(value):len(value)]
}
