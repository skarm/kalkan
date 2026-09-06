package isolated

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"syscall"
	"testing"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/ckalkan"
)

func TestErrorRoundTripPreservesSentinels(t *testing.T) {
	// Keep the public error contract independent of the wire registry: deriving
	// cases from errorSentinels would miss an accidentally removed mapping.
	sentinels := []error{
		ErrProtocol, errMetadataTooLarge,
		kalkan.ErrInvalidInput, kalkan.ErrClosed, kalkan.ErrUnavailable,
		ckalkan.ErrAlreadyOpen, ckalkan.ErrClosed, ckalkan.ErrNoLibrary,
		ckalkan.ErrUnavailable, ckalkan.ErrInvalidOutputBufferSize, ckalkan.ErrPoisoned,
		context.Canceled, context.DeadlineExceeded,
		fs.ErrInvalid, fs.ErrPermission, fs.ErrExist, fs.ErrNotExist, fs.ErrClosed,
	}
	for _, originalCause := range append([]error{errors.New("unclassified failure")}, sentinels...) {
		t.Run(originalCause.Error(), func(t *testing.T) {
			original := fmt.Errorf("worker operation failed: %w", originalCause)
			got := roundTripError(t, original)
			if got.Error() != original.Error() {
				t.Fatalf("decoded error = %q, want %q", got.Error(), original.Error())
			}
			for _, sentinel := range sentinels {
				if errors.Is(got, sentinel) != errors.Is(original, sentinel) {
					t.Errorf("decoded error changed membership of %v", sentinel)
				}
			}
		})
	}
	if roundTripError(t, nil) != nil {
		t.Fatal("nil error did not stay nil")
	}
}

func TestErrorRoundTripPreservesNativeAndJoinedCauses(t *testing.T) {
	native := &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound, Message: "сертификат не найден"}
	limit := &ckalkan.OutputBufferLimitError{Operation: "SignCMS", Requested: 999, Limit: 128}
	original := errors.Join(fmt.Errorf("first: %w", native), context.Canceled, fmt.Errorf("second: %w", limit), kalkan.ErrInvalidInput)
	got := roundTripError(t, original)
	if got.Error() != original.Error() {
		t.Fatalf("error text = %q, want %q", got.Error(), original.Error())
	}
	var decodedNative *ckalkan.KalkanError
	var decodedLimit *ckalkan.OutputBufferLimitError
	if !errors.As(got, &decodedNative) || !reflect.DeepEqual(decodedNative, native) {
		t.Fatalf("native error = %+v, want %+v", decodedNative, native)
	}
	if !errors.As(got, &decodedLimit) || !reflect.DeepEqual(decodedLimit, limit) {
		t.Fatalf("output limit error = %+v, want %+v", decodedLimit, limit)
	}
	for _, cause := range []error{context.Canceled, kalkan.ErrInvalidInput, native, &ckalkan.KalkanError{Code: ckalkan.ErrorBufferTooSmall}} {
		if !errors.Is(got, cause) {
			t.Errorf("decoded error does not match %v", cause)
		}
	}
	if code, ok := ckalkan.ErrorCodeOf(got); !ok || code != native.Code {
		t.Fatalf("native code = %v/%v, want first joined native error", code, ok)
	}
}

func TestErrorRoundTripPreservesFilesystemMembershipAndOpaqueText(t *testing.T) {
	original := &fs.PathError{Op: "open", Path: "/missing", Err: syscall.ENOENT}
	got := roundTripError(t, original)
	if got.Error() != original.Error() || !errors.Is(got, fs.ErrNotExist) {
		t.Fatalf("filesystem error = %v, want original text and fs.ErrNotExist", got)
	}
	native := &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound, Message: "invalid UTF-8: \xff"}
	got = roundTripError(t, fmt.Errorf("context: %w", native))
	var decoded *ckalkan.KalkanError
	if !errors.As(got, &decoded) || decoded.Message != native.Message || got.Error() != "context: "+native.Error() {
		t.Fatalf("opaque native error did not retain original bytes: %q / %+v", got.Error(), decoded)
	}
}

func roundTripError(t *testing.T, err error) error {
	t.Helper()
	var stream bytes.Buffer
	if err := writeMessage(&stream, message{Error: err}); err != nil {
		t.Fatal(err)
	}
	result, readErr := readMessage(&stream)
	if readErr != nil {
		t.Fatal(readErr)
	}
	return result.Error
}

func TestBinaryErrorsPreserveFullNativeCode(t *testing.T) {
	original := &ckalkan.KalkanError{Code: ckalkan.ErrorCode(^uint64(0)), Message: "native diagnostic"}
	received := roundTripError(t, original)
	var native *ckalkan.KalkanError
	if !errors.As(received, &native) || native.Code != original.Code || native.Message != original.Message {
		t.Fatalf("native error changed: %#v", received)
	}
}

func TestMalformedErrorsAreRejected(t *testing.T) {
	// Literal metadata exercises invalid tags, cause counts, sentinel bits and
	// text references without deriving expectations from the error encoder.
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"unknown native type", []byte{1, 0, 0, 0, 3}},
		{"truncated native code", []byte{1, 0, 0, 0, 1, 0}},
		{"invalid cause count", []byte{1, 0, 0, 0, 0, 255, 255, 255, 255}},
		{"truncated nested error", []byte{1, 0, 0, 0, 0, 0, 0, 0, 2, 1}},
		{"unknown sentinel bit", []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0}},
		{"truncated text reference", []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"missing text block", []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			decoder := decodePayload(wirePayload{metadata: test.data})
			if err := decoder.decodeError(0); err != nil {
				t.Fatalf("malformed metadata returned a partial error: %v", err)
			}
			if err := decoder.finish(); !errors.Is(err, ErrProtocol) {
				t.Fatalf("decode = %v, want ErrProtocol", err)
			}
		})
	}
}
