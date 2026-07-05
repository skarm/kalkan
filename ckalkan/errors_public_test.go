package ckalkan_test

import (
	"errors"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestKalkanErrorCodeExtractionAndMatching(t *testing.T) {
	err := &ckalkan.KalkanError{Code: ckalkan.ErrorInvalidPassword, Message: "bad password"}
	code, ok := ckalkan.ErrorCodeOf(err)
	if !ok {
		t.Fatal("expected ErrorCodeOf to detect KalkanError")
	}
	if code != ckalkan.ErrorInvalidPassword {
		t.Fatalf("unexpected code: got %s want %s", code.Hex(), ckalkan.ErrorInvalidPassword.Hex())
	}
	if !errors.Is(err, &ckalkan.KalkanError{Code: ckalkan.ErrorInvalidPassword}) {
		t.Fatal("expected errors.Is to match by KalkanError.Code")
	}
	if errors.Is(err, &ckalkan.KalkanError{Code: ckalkan.ErrorInvalidFlag}) {
		t.Fatal("expected errors.Is to reject a different KalkanError.Code")
	}
}

func TestKalkanErrorFormatsCodeAndNativeMessage(t *testing.T) {
	tests := []struct {
		name string
		err  *ckalkan.KalkanError
		want string
	}{
		{
			name: "without message",
			err:  &ckalkan.KalkanError{Code: ckalkan.ErrorInvalidPassword},
			want: "kalkancrypt: invalid password (0x08F00009)",
		},
		{
			name: "with message",
			err:  &ckalkan.KalkanError{Code: ckalkan.ErrorInvalidPassword, Message: "bad password"},
			want: "kalkancrypt: invalid password (0x08F00009): bad password",
		},
		{
			name: "unknown code",
			err:  &ckalkan.KalkanError{Code: ckalkan.ErrorCode(0xDEADBEEF)},
			want: "kalkancrypt: unknown error code (0xDEADBEEF)",
		},
		{
			name: "nil receiver",
			err:  nil,
			want: "<nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrorCodeLabelsCanBeLocalized(t *testing.T) {
	if got := ckalkan.ErrorInvalidPassword.String(); got != "invalid password" {
		t.Fatalf("String() = %q, want English default label", got)
	}
	if got := ckalkan.ErrorCode(0xDEADBEEF).String(); got != "unknown error code" {
		t.Fatalf("unknown String() = %q, want English unknown label", got)
	}

	tests := []struct {
		name     string
		code     ckalkan.ErrorCode
		language ckalkan.ErrorLanguage
		want     string
	}{
		{
			name:     "default english string",
			code:     ckalkan.ErrorInvalidPassword,
			language: ckalkan.ErrorLanguageEnglish,
			want:     "invalid password",
		},
		{
			name:     "russian label",
			code:     ckalkan.ErrorInvalidPassword,
			language: ckalkan.ErrorLanguageRussian,
			want:     "неправильный пароль",
		},
		{
			name:     "unsupported language falls back to english",
			code:     ckalkan.ErrorInvalidPassword,
			language: ckalkan.ErrorLanguage("kk"),
			want:     "invalid password",
		},
		{
			name:     "unknown russian label",
			code:     ckalkan.ErrorCode(0xDEADBEEF),
			language: ckalkan.ErrorLanguageRussian,
			want:     "неизвестный код ошибки",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.code.Label(tt.language); got != tt.want {
				t.Fatalf("Label(%q) = %q, want %q", tt.language, got, tt.want)
			}
		})
	}
}

func TestKalkanErrorCanBeFormattedInRussian(t *testing.T) {
	err := &ckalkan.KalkanError{Code: ckalkan.ErrorInvalidPassword, Message: "bad password"}
	want := "kalkancrypt: неправильный пароль (0x08F00009): bad password"

	if got := err.Format(ckalkan.ErrorLanguageRussian); got != want {
		t.Fatalf("Format(Russian) = %q, want %q", got, want)
	}
}

func TestErrorCodeHexPadsSDKCodesToEightDigits(t *testing.T) {
	tests := map[ckalkan.ErrorCode]string{
		ckalkan.ErrorOK:                "0x00000000",
		ckalkan.ErrorInvalidFlag:       "0x08F00007",
		ckalkan.ErrorCode(0x1):         "0x00000001",
		ckalkan.ErrorCode(0x123456789): "0x123456789",
	}
	for code, want := range tests {
		if got := code.Hex(); got != want {
			t.Fatalf("ErrorCode(%d).Hex() = %q, want %q", code, got, want)
		}
	}
}
