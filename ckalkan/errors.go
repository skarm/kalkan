package ckalkan

import (
	"errors"
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

// Label returns a human-readable label for the KalkanCrypt error code in
// language. Unsupported languages fall back to English.
func (c ErrorCode) Label(language ErrorLanguage) string {
	labels, unknownLabel := errorLabelsForLanguage(language)
	if label, ok := labels[c]; ok {
		return label
	}

	return unknownLabel
}

// Hex formats the error code as an eight-digit hexadecimal value.
func (c ErrorCode) Hex() string {
	const width = 8

	hex := strings.ToUpper(strconv.FormatUint(uint64(c), 16))
	if len(hex) < width {
		hex = strings.Repeat("0", width-len(hex)) + hex
	}

	return "0x" + hex
}

// KalkanError is returned when a KalkanCrypt function returns a non-zero code.
type KalkanError struct {
	Code    ErrorCode
	Message string
}

// Error formats the KalkanCrypt error code and optional native message.
func (e *KalkanError) Error() string {
	return e.Format(ErrorLanguageEnglish)
}

// Format formats the KalkanCrypt error code and optional native message using
// language. Unsupported languages fall back to English.
func (e *KalkanError) Format(language ErrorLanguage) string {
	if e == nil {
		return "<nil>"
	}

	if e.Message == "" {
		return "kalkancrypt: " + e.Code.Label(language) + " (" + e.Code.Hex() + ")"
	}

	return "kalkancrypt: " + e.Code.Label(language) + " (" + e.Code.Hex() + "): " + e.Message
}

// Is reports whether target is a KalkanError with the same code.
func (e *KalkanError) Is(target error) bool {
	t, ok := errors.AsType[*KalkanError](target)

	return ok && e != nil && t != nil && e.Code == t.Code
}

// ErrorCodeOf extracts a KalkanCrypt code from an error.
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
