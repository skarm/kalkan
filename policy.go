package kalkan

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

func validateNativePathString(field, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrInvalidInput, field)
	}

	if err := rejectEmbeddedNUL(field, path); err != nil {
		return "", err
	}

	return path, nil
}

func rejectEmbeddedNUL(field, value string) error {
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%w: %s contains embedded NUL", ErrInvalidInput, field)
	}

	return nil
}

func normalizeNativeHTTPURL(field, value string) (string, error) {
	trimmedURL := strings.TrimSpace(value)
	if trimmedURL == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrInvalidInput, field)
	}

	if err := rejectEmbeddedNUL(field, trimmedURL); err != nil {
		return "", err
	}

	if strings.ContainsFunc(trimmedURL, unicode.IsSpace) {
		return "", fmt.Errorf("%w: %s contains whitespace", ErrInvalidInput, field)
	}

	parsedURL, err := url.Parse(trimmedURL)
	if err != nil {
		return "", fmt.Errorf("%w: %s is invalid: %w", ErrInvalidInput, field, err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("%w: %s must use http or https", ErrInvalidInput, field)
	}

	if parsedURL.Host == "" {
		return "", fmt.Errorf("%w: %s host is empty", ErrInvalidInput, field)
	}

	return trimmedURL, nil
}
