package ckalkan_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestKalkanErrorMatchingDoesNotUnwrapTarget(t *testing.T) {
	plain := &ckalkan.KalkanError{Code: ckalkan.ErrorBufferTooSmall}
	limit := &ckalkan.OutputBufferLimitError{Operation: "SignData", Requested: 1025, Limit: 1024}
	var nilKalkan *ckalkan.KalkanError

	for _, test := range []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{name: "same code", err: plain, target: &ckalkan.KalkanError{Code: plain.Code, Message: "different message"}, want: true},
		{name: "different code", err: plain, target: &ckalkan.KalkanError{Code: ckalkan.ErrorSign}},
		{name: "wrapped source", err: fmt.Errorf("wrapped: %w", plain), target: plain, want: true},
		{name: "joined source", err: errors.Join(errors.New("other"), plain), target: plain, want: true},
		{name: "wrapped target", err: plain, target: fmt.Errorf("wrapped: %w", plain)},
		{name: "joined target", err: plain, target: errors.Join(errors.New("other"), plain)},
		{name: "typed limit source", err: limit, target: plain, want: true},
		{name: "typed limit target", err: plain, target: limit},
		{name: "nil receiver", err: nilKalkan, target: plain},
		{name: "typed nil target", err: plain, target: nilKalkan},
		{name: "nil target", err: plain},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := errors.Is(test.err, test.target); got != test.want {
				t.Fatalf("errors.Is(%v, %v) = %t, want %t", test.err, test.target, got, test.want)
			}
		})
	}

	if code, ok := ckalkan.ErrorCodeOf(fmt.Errorf("wrapped: %w", limit)); !ok || code != ckalkan.ErrorBufferTooSmall {
		t.Fatalf("ErrorCodeOf = (%v, %t), want ErrorBufferTooSmall", code, ok)
	}
}
