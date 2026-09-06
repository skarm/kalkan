package isolated

import (
	"context"
	"errors"
	"io/fs"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/ckalkan"
)

// Error text travels in raw blocks. The header stores sentinel bits, an optional
// concrete native error and direct unwrap links. Both directions bound depth.
func (e *payloadEncoder) encodeError(err error, depth int) {
	e.boolean(err != nil)

	if err == nil || e.err != nil {
		return
	}

	if depth >= 32 {
		e.err = errMetadataTooLarge
		return
	}

	//nolint:errorlint // Preserve the concrete error at this exact unwrap position.
	switch value := err.(type) {
	case *ckalkan.KalkanError:
		e.uint32(1)
		e.uint64(uint64(value.Code))
		e.text(value.Message)
	case *ckalkan.OutputBufferLimitError:
		e.uint32(2)
		e.text(value.Operation)
		e.uint64(value.Requested)
		e.uint64(value.Limit)
	default:
		e.uint32(0)
	}

	var causes []error
	//nolint:errorlint // Walk direct links rather than flattening errors.As matches.
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		causes = wrapped.Unwrap()
	case interface{ Unwrap() error }:
		causes = []error{wrapped.Unwrap()}
	}

	if e.length(len(causes), causes != nil) {
		for _, cause := range causes {
			e.encodeError(cause, depth+1)
		}
	}

	if e.err != nil {
		return
	}

	var sentinels uint64

	for i, value := range errorSentinels() {
		if errors.Is(err, value) {
			sentinels |= 1 << i
		}
	}

	e.uint64(sentinels)
	e.text(err.Error())
}

func (d *payloadDecoder) decodeError(depth int) error {
	if !d.boolean() || d.err != nil {
		return nil
	}

	if depth >= 32 {
		d.err = malformedResult()
		return nil
	}

	var causes []error

	switch d.uint32() {
	case 0:
	case 1:
		causes = append(causes, &ckalkan.KalkanError{Code: ckalkan.ErrorCode(d.uint64()), Message: d.text()})
	case 2:
		causes = append(causes, &ckalkan.OutputBufferLimitError{Operation: d.text(), Requested: d.uint64(), Limit: d.uint64()})
	default:
		d.err = malformedResult()
		return nil
	}

	for range d.length(1) {
		if cause := d.decodeError(depth + 1); cause != nil {
			causes = append(causes, cause)
		}
	}

	if d.err != nil {
		return nil
	}

	known := errorSentinels()

	bits := d.uint64()
	if bits>>len(known) != 0 {
		d.err = malformedResult()
		return nil
	}

	for i, value := range known {
		if bits&(1<<i) != 0 {
			causes = append(causes, value)
		}
	}

	result := &remoteError{message: d.text(), causes: causes}
	if d.err != nil {
		return nil
	}

	return result
}

type remoteError struct {
	message string
	causes  []error
}

func (err *remoteError) Error() string   { return err.message }
func (err *remoteError) Unwrap() []error { return err.causes }

func errorSentinels() []error {
	return []error{
		ErrProtocol, errMetadataTooLarge,
		kalkan.ErrInvalidInput, kalkan.ErrClosed, kalkan.ErrUnavailable,
		ckalkan.ErrAlreadyOpen, ckalkan.ErrClosed, ckalkan.ErrNoLibrary, ckalkan.ErrUnavailable,
		ckalkan.ErrInvalidOutputBufferSize, ckalkan.ErrPoisoned,
		context.Canceled, context.DeadlineExceeded,
		fs.ErrInvalid, fs.ErrPermission, fs.ErrExist, fs.ErrNotExist, fs.ErrClosed,
	}
}
