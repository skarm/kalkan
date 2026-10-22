package ckalkan_test

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestNewReturnsErrorForMissingLibrary(t *testing.T) {
	_, err := ckalkan.New(ckalkan.WithLibrary(filepath.Join(t.TempDir(), "missing.so")))
	if err == nil {
		t.Fatal("expected New to fail for a missing library")
	}
}

func TestConstantsMatchKnownSDKValues(t *testing.T) {
	checks := map[string]bool{
		"StorePKCS12":                ckalkan.StorePKCS12 == 0x00000001,
		"CertB64":                    ckalkan.CertB64 == 0x00000104,
		"UseOCSP":                    ckalkan.UseOCSP == 0x00000404,
		"XMLExclC14N":                ckalkan.XMLExclC14N == 0x01000010,
		"CertPropPubKey":             ckalkan.CertPropPubKey == 0x0000081d,
		"CertPropOCSP":               ckalkan.CertPropOCSP == 0x0000081f,
		"CertPropGetCRL":             ckalkan.CertPropGetCRL == 0x00000820,
		"CertPropGetDeltaCRL":        ckalkan.CertPropGetDeltaCRL == 0x00000821,
		"WithTimestamp":              ckalkan.WithTimestamp == 0x00000100,
		"GetOCSPResponse":            ckalkan.GetOCSPResponse == 0x00080000,
		"HashGOST2015_256Flag":       ckalkan.HashGOST2015_256 == 0x00100000,
		"HashGOST2015_512Flag":       ckalkan.HashGOST2015_512 == 0x00200000,
		"SHA256String":               ckalkan.SHA256 == "sha256",
		"GOST95String":               ckalkan.GOST95 == "Gost34311_95",
		"GOST2015_256String":         ckalkan.GOST2015_256 == "GostR3411_2015_256",
		"GOST2015_512String":         ckalkan.GOST2015_512 == "GostR3411_2015_512",
		"ErrorParam":                 ckalkan.ErrorParam == 0x08f00300,
		"ErrorVerifyTSHash":          ckalkan.ErrorVerifyTSHash == 0x08f00054,
		"ErrorXADEST":                ckalkan.ErrorXADESTFailed == 0x08f00055,
		"ErrorOCSPMalformedRequest":  ckalkan.ErrorOCSPRespStatMalformedRequest == 0x08f00056,
		"ErrorOCSPInternalError":     ckalkan.ErrorOCSPRespStatInternalError == 0x08f00057,
		"ErrorOCSPTryLater":          ckalkan.ErrorOCSPRespStatTryLater == 0x08f00058,
		"ErrorOCSPSigRequired":       ckalkan.ErrorOCSPRespStatSigRequired == 0x08f00059,
		"ErrorOCSPUnauthorized":      ckalkan.ErrorOCSPRespStatUnauthorized == 0x08f0005a,
		"ErrorVerifyIssuerSerialV2":  ckalkan.ErrorVerifyIssuerSerialV2 == 0x08f0005b,
		"ErrorOCSPCheckCertFromResp": ckalkan.ErrorOCSPCheckCertFromResp == 0x08f0005c,
		"ErrorCRLExpired":            ckalkan.ErrorCRLExpired == 0x08f0005d,
	}
	for name, ok := range checks {
		if !ok {
			t.Fatalf("constant %s has unexpected value", name)
		}
	}
}

func TestFlagsMatchSDKHeader(t *testing.T) {
	header, err := os.ReadFile("internal/kalkancrypt/KalkanCrypt.h")
	if err != nil {
		t.Fatal(err)
	}
	definitions := make(map[string]uint64)
	for line := range strings.SplitSeq(string(header), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "#define" {
			continue
		}
		value, err := strconv.ParseUint(fields[2], 0, 32)
		if err == nil {
			definitions[fields[1]] = value
		}
	}
	for name, flag := range map[string]ckalkan.Flag{
		"KC_SIGN_DRAFT": ckalkan.SignDraft, "KC_SIGN_CMS": ckalkan.SignCMS,
		"KC_IN_PEM": ckalkan.InPEM, "KC_IN_DER": ckalkan.InDER,
		"KC_IN_BASE64": ckalkan.InBase64, "KC_IN2_BASE64": ckalkan.In2Base64,
		"KC_DETACHED_DATA": ckalkan.DetachedData, "KC_WITH_CERT": ckalkan.WithCert,
		"KC_WITH_TIMESTAMP": ckalkan.WithTimestamp, "KC_IN_FILE": ckalkan.InFile,
		"KC_OUT_PEM": ckalkan.OutPEM, "KC_OUT_DER": ckalkan.OutDER,
		"KC_OUT_BASE64": ckalkan.OutBase64, "KC_NOCHECKCERTTIME": ckalkan.NoCheckCertTime,
		"KC_PROXY_OFF": ckalkan.ProxyOff, "KC_PROXY_ON": ckalkan.ProxyOn,
		"KC_PROXY_AUTH": ckalkan.ProxyAuth, "KC_GET_OCSP_RESPONSE": ckalkan.GetOCSPResponse,
		"KC_HASH_SHA256": ckalkan.HashSHA256, "KC_HASH_GOST95": ckalkan.HashGOST95,
		"KC_HASH_GOST15_256": ckalkan.HashGOST2015_256, "KC_HASH_GOST15_512": ckalkan.HashGOST2015_512,
		"KC_XML_INCL_C14N": ckalkan.XMLInclC14N, "KC_XML_INCL_C14NCOMMENT": ckalkan.XMLInclC14NComment,
		"KC_XML_INCL_C14N11": ckalkan.XMLInclC14N11, "KC_XML_INCL_C14N11COMMENT": ckalkan.XMLInclC14N11Comment,
		"KC_XML_EXCL_C14N": ckalkan.XMLExclC14N, "KC_XML_EXCL_C14NCOMMENT": ckalkan.XMLExclC14NComment,
		"KC_XMLC_INCL_C14N": ckalkan.XMLCInclC14N, "KC_XMLC_INCL_C14NCOMMENT": ckalkan.XMLCInclC14NComment,
		"KC_XMLC_INCL_C14N11": ckalkan.XMLCInclC14N11, "KC_XMLC_INCL_C14N11COMMENT": ckalkan.XMLCInclC14N11Comment,
		"KC_XMLC_EXCL_C14N": ckalkan.XMLCExclC14N, "KC_XMLC_EXCL_C14NCOMMENT": ckalkan.XMLCExclC14NComment,
	} {
		t.Run(name, func(t *testing.T) {
			value, ok := definitions[name]
			if !ok || uint64(flag) != value {
				t.Fatalf("Go flag = %#x, SDK header value = %#x (found=%v)", flag, value, ok)
			}
		})
	}
}

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

func TestErrorCodeHexPadsCodesToEightDigits(t *testing.T) {
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
