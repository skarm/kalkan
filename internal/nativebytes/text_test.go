package nativebytes

import "testing"

func TestBeforeNULPreservesBorrowedText(t *testing.T) {
	for _, test := range []struct {
		name  string
		input []byte
		want  string
	}{
		{name: "nil"},
		{name: "empty", input: []byte{}},
		{name: "plain", input: []byte("plain"), want: "plain"},
		{name: "padding", input: []byte("value\x00garbage"), want: "value"},
		{name: "empty C string", input: []byte{0, 'x'}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := BeforeNUL(test.input)
			if string(got) != test.want || len(got) != cap(got) {
				t.Fatalf("BeforeNUL = %q (len/cap %d/%d), want %q with bounded capacity", got, len(got), cap(got), test.want)
			}
			if (got == nil) != (test.input == nil) {
				t.Fatal("nil/empty distinction changed")
			}
			if len(got) > 0 && &got[0] != &test.input[0] {
				t.Fatal("text was copied instead of borrowing input")
			}
		})
	}
}
