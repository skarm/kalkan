package ckalkan

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrorLanguage selects a human-readable KalkanCrypt error label language.
type ErrorLanguage string

const (
	// ErrorLanguageEnglish selects English error labels.
	ErrorLanguageEnglish ErrorLanguage = "en"
	// ErrorLanguageRussian selects Russian error labels.
	ErrorLanguageRussian ErrorLanguage = "ru"
)

// String returns a human-readable English label for the KalkanCrypt error code.
func (c ErrorCode) String() string {
	return c.Label(ErrorLanguageEnglish)
}

// Label returns the KalkanCrypt error label in language.
// Unsupported languages use English.
func (c ErrorCode) Label(language ErrorLanguage) string {
	return errorLabelForLanguage(c, language)
}

// Hex returns c as uppercase hexadecimal with a 0x prefix and at least eight
// digits.
func (c ErrorCode) Hex() string {
	const width = 8

	hex := strings.ToUpper(strconv.FormatUint(uint64(c), 16))
	if len(hex) < width {
		hex = strings.Repeat("0", width-len(hex)) + hex
	}

	return "0x" + hex
}

// KalkanError reports a nonzero KalkanCrypt status code.
type KalkanError struct {
	// Code is the non-zero status returned by KalkanCrypt.
	Code ErrorCode
	// Message is optional diagnostic text returned by the native library or
	// supplied by the wrapper.
	Message string
}

// OutputBufferLimitError reports that an output buffer requires more bytes
// than the active hard limit permits.
type OutputBufferLimitError struct {
	// Operation names the native wrapper operation without input data.
	Operation string
	// Requested is the requested buffer capacity in bytes.
	Requested uint64
	// Limit is the active hard limit in bytes.
	Limit uint64
}

// Error returns the buffer limit message with the [ErrorBufferTooSmall] label.
func (e *OutputBufferLimitError) Error() string {
	if e == nil {
		return "<nil>"
	}

	operation := e.Operation
	if operation == "" {
		operation = "output"
	}

	return (&KalkanError{
		Code: ErrorBufferTooSmall,
		Message: fmt.Sprintf(
			"%s requires an output buffer of at least %d bytes, exceeding hard limit %d bytes",
			operation,
			e.Requested,
			e.Limit,
		),
	}).Error()
}

// Unwrap returns a [KalkanError] with code [ErrorBufferTooSmall].
func (e *OutputBufferLimitError) Unwrap() error {
	return &KalkanError{Code: ErrorBufferTooSmall}
}

// Error returns the English error label, hexadecimal code, and optional
// diagnostic message.
func (e *KalkanError) Error() string {
	return e.Format(ErrorLanguageEnglish)
}

// Format returns the KalkanCrypt error code and optional native message in
// language.
// Unsupported languages use English.
func (e *KalkanError) Format(language ErrorLanguage) string {
	if e == nil {
		return "<nil>"
	}

	if e.Message == "" {
		return "kalkancrypt: " + e.Code.Label(language) + " (" + e.Code.Hex() + ")"
	}

	return "kalkancrypt: " + e.Code.Label(language) + " (" + e.Code.Hex() + "): " + e.Message
}

// Is reports whether target itself is a KalkanError with the same code.
// It does not unwrap target.
// [errors.Is] traverses the source error tree.
func (e *KalkanError) Is(target error) bool {
	//noinspection GoTypeAssertionOnErrors
	t, ok := target.(*KalkanError)

	return ok && e != nil && t != nil && e.Code == t.Code
}

// ErrorCodeOf returns the first [KalkanError] code in err's error tree.
// It returns zero and false if no KalkanError matches or the first match is nil.
func ErrorCodeOf(err error) (ErrorCode, bool) {
	if ke, ok := errors.AsType[*KalkanError](err); ok && ke != nil {
		return ke.Code, true
	}

	return 0, false
}

func errorFromCode(code ErrorCode, message string) error {
	if code == ErrorOK {
		return nil
	}

	return &KalkanError{Code: code, Message: message}
}
