package kalkan

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

func FuzzNormalizeNativeHTTPURL(f *testing.F) {
	for _, value := range []string{
		"http://ocsp.pki.gov.kz",
		" https://example.test/ocsp ",
		"ftp://example.test",
		"http://user@example.test",
		"http://example.test/path#fragment",
		"http://example.test/bad path",
		"http://example.test\x00/ocsp",
	} {
		f.Add(value)
	}

	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}

		normalized, err := normalizeNativeHTTPURL("fuzz endpoint", value)
		if err != nil {
			return
		}

		parsed, err := url.Parse(normalized)
		if err != nil {
			t.Fatalf("accepted URL %q cannot be parsed: %v", normalized, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			t.Fatalf("accepted URL scheme = %q", parsed.Scheme)
		}
		if parsed.Host == "" {
			t.Fatalf("accepted URL violates endpoint invariants: %q", normalized)
		}
		if strings.ContainsRune(normalized, '\x00') || strings.ContainsFunc(normalized, unicode.IsSpace) {
			t.Fatalf("accepted URL contains NUL or whitespace: %q", normalized)
		}

		again, err := normalizeNativeHTTPURL("fuzz endpoint", normalized)
		if err != nil || again != normalized {
			t.Fatalf("normalization is not idempotent: first %q, second %q, error %v", normalized, again, err)
		}
	})
}

func FuzzZIPOutputPlan(f *testing.F) {
	for _, value := range []string{"signed.zip", "/tmp/signed.ZIP", "", ".zip", "bad\x00.zip", "nested/archive.zip"} {
		f.Add(value)
	}

	f.Fuzz(func(t *testing.T, outputPath string) {
		if len(outputPath) > 4096 {
			t.Skip()
		}

		plan, err := zipOutputPlan(outputPath)
		if err != nil {
			return
		}
		if plan.nativeName == "" {
			t.Fatal("zipOutputPlan accepted an empty native name")
		}
		if filepath.Ext(plan.desiredPath) != ".zip" {
			t.Fatalf("desired ZIP path = %q, want lowercase .zip extension", plan.desiredPath)
		}
		if strings.ContainsRune(plan.desiredPath, '\x00') {
			t.Fatalf("desired ZIP path contains NUL: %q", plan.desiredPath)
		}
	})
}

func FuzzValidateZIPPath(f *testing.F) {
	for _, value := range []string{"", "archive.zip", "../archive.zip", "archive\x00.zip", " archive.zip "} {
		f.Add(value)
	}

	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > 4096 {
			t.Skip()
		}

		got, err := validateNativePathString("ZIP path", path)
		invalid := path == "" || strings.ContainsRune(path, '\x00')
		if invalid {
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("validateNativePathString(%q) error = %v, want ErrInvalidInput", path, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("validateNativePathString(%q) returned unexpected error: %v", path, err)
		}
		if got != path {
			t.Fatalf("validated path = %q, want byte-preserving %q", got, path)
		}
	})
}

func FuzzCertificateValidationInput(f *testing.F) {
	f.Add([]byte("certificate"), uint8(0))
	f.Add([]byte("Y2VydGlmaWNhdGU="), uint8(1))
	f.Add([]byte(" "), uint8(1))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n"), uint8(2))
	f.Add([]byte(""), uint8(2))

	f.Fuzz(func(t *testing.T, data []byte, kind uint8) {
		const maxSize = int64(64 << 10)
		if len(data) > int(maxSize)+1 {
			t.Skip()
		}

		var source Source
		switch kind % 3 {
		case 0:
			source = DER(data)
		case 1:
			source = Base64(data)
		case 2:
			source = PEM(data)
		}

		result, err := certificateValidationInput(source, maxSize)
		if err != nil {
			return
		}
		if len(result) == 0 {
			t.Fatal("certificate preprocessing accepted empty output")
		}
		if int64(len(result)) > maxSize {
			t.Fatalf("certificate preprocessing returned %d bytes, limit is %d", len(result), maxSize)
		}
	})
}

func FuzzValidateBytesSize(f *testing.F) {
	f.Add([]byte(""), int64(1))
	f.Add([]byte("payload"), int64(7))
	f.Add([]byte("payload"), int64(6))
	f.Add([]byte("payload"), int64(0))

	f.Fuzz(func(t *testing.T, data []byte, rawLimit int64) {
		if len(data) > 1<<20 {
			t.Skip()
		}

		limit := rawLimit % (1 << 20)
		err := validateBytesSize(data, "fuzz input", limit)
		wantRejection := limit > 0 && int64(len(data)) > limit
		if wantRejection && !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("validateBytesSize(len=%d, limit=%d) error = %v, want ErrInvalidInput", len(data), limit, err)
		}
		if !wantRejection && err != nil {
			t.Fatalf("validateBytesSize(len=%d, limit=%d) error = %v, want nil", len(data), limit, err)
		}
	})
}
