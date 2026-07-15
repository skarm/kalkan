package ckalkan

import (
	"testing"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestXMLSigningTrimsTerminator(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) ([]byte, error)
	}{
		{
			name: "SignXML",
			call: func(client *Client) ([]byte, error) {
				return client.SignXML(SignXMLRequest{XML: []byte("<root/>")})
			},
		},
		{
			name: "SignWSSE",
			call: func(client *Client) ([]byte, error) {
				return client.SignWSSE(SignWSSERequest{XML: []byte("<root/>")})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nativeOutput := []byte("<signed/>\x00")
			ctx := &fakeNativeContext{
				signXMLFunc: func(kalkancrypt.SignXMLCall) (kalkancrypt.BufferResult, error) {
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: nativeOutput, OutLen: len(nativeOutput)}, nil
				},
				signWSSEFunc: func(kalkancrypt.SignWSSECall) (kalkancrypt.BufferResult, error) {
					return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: nativeOutput, OutLen: len(nativeOutput)}, nil
				},
			}
			client := &Client{ctx: ctx, config: defaultConfig()}

			got, err := test.call(client)
			if err != nil {
				t.Fatalf("%s returned error: %v", test.name, err)
			}
			if string(got) != "<signed/>" {
				t.Fatalf("%s output = %q, want XML without NUL terminator", test.name, got)
			}
			if &got[0] != &nativeOutput[0] {
				t.Fatalf("%s copied native output", test.name)
			}
		})
	}
}
