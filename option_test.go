package kalkan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestOpenRequiresLibraryPath(t *testing.T) {
	_, err := Open(context.Background())
	if err == nil || !strings.Contains(err.Error(), "library path is required") {
		t.Fatalf("Open error = %v, want required library path error", err)
	}
}

func TestOpenUsesDefaultNetworkURLs(t *testing.T) {
	var sawTSA bool
	native := &fakeNative{
		setTSAURLFunc: func(tsaURL string) error {
			sawTSA = true
			if tsaURL != defaultTSAURL {
				t.Fatalf("TSA URL = %q, want default %q", tsaURL, defaultTSAURL)
			}
			return nil
		},
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			if req.ValidationPath != defaultOCSPURL {
				t.Fatalf("OCSP URL = %q, want default %q", req.ValidationPath, defaultOCSPURL)
			}
			return ckalkan.ValidateCertificateResult{Info: "ok"}, nil
		},
	}

	client, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath(testLibraryPath()),
	}, func(config) (closer, error) {
		return native, nil
	})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	if !sawTSA {
		t.Fatal("Open did not configure the default TSA URL")
	}

	_, err = client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate: Bytes([]byte("cert")),
		Mode:        CertificateValidationOCSP,
	})
	if err != nil {
		t.Fatalf("ValidateCertificate returned error: %v", err)
	}
}

func TestOpenRejectsRelativeLibraryPath(t *testing.T) {
	_, err := Open(context.Background(), WithLibraryPath("KalkanCrypt.dll"))
	if err == nil || !strings.Contains(err.Error(), "absolute library path") {
		t.Fatalf("Open error = %v, want absolute library path error", err)
	}
}

func TestOpenPreservesLibraryPath(t *testing.T) {
	var factoryCalls int

	_, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath(" \t" + testLibraryPath() + "\n"),
	}, func(config) (closer, error) {
		factoryCalls++
		return &fakeNative{}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "absolute library path") {
		t.Fatalf("Open error = %v, want absolute library path error", err)
	}
	if factoryCalls != 0 {
		t.Fatalf("native factory calls = %d, want 0", factoryCalls)
	}
}

func TestOpenRejectsNULInLibraryPath(t *testing.T) {
	var factoryCalls int

	_, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath("/tmp/lib.so\x00suffix"),
	}, func(config) (closer, error) {
		factoryCalls++
		return &fakeNative{}, nil
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("Open error = %v, want ErrInvalidInput embedded NUL rejection", err)
	}
	if factoryCalls != 0 {
		t.Fatalf("native factory calls = %d, want 0", factoryCalls)
	}
}

func TestValidateNativePathStringPolicy(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
		err  string
	}{
		{name: "empty", path: "", err: "native path is empty"},
		{name: "preserve whitespace", path: " \t/path/to/file\n", want: " \t/path/to/file\n"},
		{name: "whitespace-only is non-empty path", path: " \t\n ", want: " \t\n "},
		{name: "embedded NUL", path: "/tmp/a\x00b", err: "NUL"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := validateNativePathString("native path", test.path)
			if test.err != "" {
				if err == nil || !strings.Contains(err.Error(), test.err) {
					t.Fatalf("validateNativePathString error = %v, want %q", err, test.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateNativePathString returned error: %v", err)
			}
			if got != test.want {
				t.Fatalf("validateNativePathString = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNormalizeNativeHTTPURLPolicy(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		err   string
	}{
		{name: "trim", value: " \thttps://example.test/ocsp\n", want: "https://example.test/ocsp"},
		{name: "empty", value: " \t\n ", err: "OCSP URL is empty"},
		{name: "embedded NUL", value: "https://example.test\x00/ocsp", err: "NUL"},
		{name: "internal whitespace", value: "https://example.test/bad path", err: "whitespace"},
		{name: "scheme", value: "ftp://example.test/ocsp", err: "http or https"},
		{name: "host", value: "https:/example.test/ocsp", err: "host is empty"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeNativeHTTPURL("OCSP URL", test.value)
			if test.err != "" {
				if err == nil || !strings.Contains(err.Error(), test.err) {
					t.Fatalf("normalizeNativeHTTPURL error = %v, want %q", err, test.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeNativeHTTPURL returned error: %v", err)
			}
			if got != test.want {
				t.Fatalf("normalizeNativeHTTPURL = %q, want %q", got, test.want)
			}
		})
	}
}

func TestOpenRejectsInvalidURLs(t *testing.T) {
	tests := []struct {
		name   string
		option Option
		want   string
	}{
		{name: "TSA whitespace", option: WithTSAURL(" \t\n "), want: "TSA URL is empty"},
		{name: "OCSP whitespace", option: WithOCSPURL(" \t\n "), want: "OCSP URL is empty"},
		{name: "TSA NUL", option: WithTSAURL("http://tsa.example\x00/path"), want: "NUL"},
		{name: "OCSP NUL", option: WithOCSPURL("http://ocsp.example\x00/path"), want: "NUL"},
		{name: "TSA internal space", option: WithTSAURL("http://tsa.example/bad path"), want: "whitespace"},
		{name: "OCSP tab", option: WithOCSPURL("http://ocsp.example/\tbad"), want: "whitespace"},
		{name: "TSA unsupported scheme", option: WithTSAURL("ftp://tsa.example/path"), want: "http or https"},
		{name: "OCSP missing scheme", option: WithOCSPURL("ocsp.example/path"), want: "http or https"},
		{name: "TSA missing host", option: WithTSAURL("https:/tsa.example/path"), want: "host"},
		{name: "OCSP malformed", option: WithOCSPURL("http://[::1"), want: "invalid"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var factoryCalls int
			_, err := openWithLibraryFactory(context.Background(), []Option{
				WithLibraryPath(testLibraryPath()),
				test.option,
			}, func(config) (closer, error) {
				factoryCalls++
				return &fakeNative{}, nil
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Open error = %v, want %q", err, test.want)
			}
			if factoryCalls != 0 {
				t.Fatalf("native factory calls = %d, want 0", factoryCalls)
			}
		})
	}
}

func TestOpenTrimsConfiguredTSAAndOCSPURLs(t *testing.T) {
	var sawTSA bool
	native := &fakeNative{
		setTSAURLFunc: func(tsaURL string) error {
			sawTSA = true
			if tsaURL != "http://tsa.example/path" {
				t.Fatalf("TSA URL = %q, want trimmed URL", tsaURL)
			}
			return nil
		},
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			if req.ValidationPath != "http://ocsp.example/path" {
				t.Fatalf("OCSP URL = %q, want trimmed URL", req.ValidationPath)
			}
			return ckalkan.ValidateCertificateResult{Info: "ok"}, nil
		},
	}

	client, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath(testLibraryPath()),
		WithTSAURL(" \thttp://tsa.example/path\n"),
		WithOCSPURL(" \thttp://ocsp.example/path\n"),
	}, func(config) (closer, error) {
		return native, nil
	})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if !sawTSA {
		t.Fatal("Open did not configure TSA URL")
	}

	_, err = client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate: Bytes([]byte("cert")),
		Mode:        CertificateValidationOCSP,
	})
	if err != nil {
		t.Fatalf("ValidateCertificate returned error: %v", err)
	}
}

func TestOpenMapsMaxBufferSize(t *testing.T) {
	const wantMaxOutputBufferSize = 2 << 20

	client, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath(testLibraryPath()),
		WithMaxOutputBufferSize(wantMaxOutputBufferSize),
	}, func(cfg config) (closer, error) {
		if cfg.maxOutputBufferSize != wantMaxOutputBufferSize {
			t.Fatalf("max output buffer size = %d, want %d", cfg.maxOutputBufferSize, wantMaxOutputBufferSize)
		}

		return &fakeNative{}, nil
	})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestClientHasNoDefaultLogger(t *testing.T) {
	handler := newRecordingHandler()
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(originalLogger)

	client := &Client{
		library: &fakeNative{
			hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
				return []byte("digest"), nil
			},
		},
	}

	if _, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("payload"))}); err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	if records := handler.Records(); len(records) != 0 {
		t.Fatalf("default slog records = %v, want none without WithLogger", records)
	}
}

func TestWithLoggerRecordsNativeCallSuccess(t *testing.T) {
	handler := newRecordingHandler()

	client, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath(testLibraryPath()),
		WithLogger(slog.New(handler)),
	}, func(config) (closer, error) {
		return &fakeNative{
			hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
				return []byte("digest"), nil
			},
		}, nil
	})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	if _, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("payload"))}); err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	records := handler.Records()
	if !hasLogRecord(records, slog.LevelDebug, "kalkan native call completed", map[string]string{
		"component": "kalkan",
		"operation": "Hash",
	}) {
		t.Fatalf("log records = %v, want successful Hash native call record", records)
	}
}

func TestWithLoggerRecordsNativeCallError(t *testing.T) {
	handler := newRecordingHandler()
	nativeErr := errors.New("native hash failed")

	client, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath(testLibraryPath()),
		WithLogger(slog.New(handler)),
	}, func(config) (closer, error) {
		return &fakeNative{
			hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
				return nil, nativeErr
			},
		}, nil
	})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	_, err = client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("payload"))})
	if !errors.Is(err, nativeErr) {
		t.Fatalf("Hash error = %v, want native error", err)
	}

	records := handler.Records()
	if !hasLogRecord(records, slog.LevelError, "kalkan native call failed", map[string]string{
		"component": "kalkan",
		"operation": "Hash",
		"error":     nativeErr.Error(),
	}) {
		t.Fatalf("log records = %v, want failed Hash native call record", records)
	}
}

func TestWithLoggerRecordsClose(t *testing.T) {
	handler := newRecordingHandler()

	client, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath(testLibraryPath()),
		WithLogger(slog.New(handler)),
	}, func(config) (closer, error) {
		return &fakeNative{}, nil
	})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	records := handler.Records()
	if !hasLogRecord(records, slog.LevelDebug, "kalkan native call completed", map[string]string{
		"component": "kalkan",
		"operation": "Close",
	}) {
		t.Fatalf("log records = %v, want successful Close native call record", records)
	}
}

type recordedLog struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

type recordingHandler struct {
	sink  *recordingSink
	attrs []slog.Attr
}

type recordingSink struct {
	mu      sync.Mutex
	records []recordedLog
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{sink: &recordingSink{}}
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := make(map[string]string)
	for _, attr := range h.attrs {
		recordStringAttr(attrs, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		recordStringAttr(attrs, attr)

		return true
	})

	h.sink.mu.Lock()
	h.sink.records = append(h.sink.records, recordedLog{
		level: record.Level,
		msg:   record.Message,
		attrs: attrs,
	})
	h.sink.mu.Unlock()

	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	combined = append(combined, h.attrs...)
	combined = append(combined, attrs...)

	return &recordingHandler{sink: h.sink, attrs: combined}
}

func (h *recordingHandler) WithGroup(string) slog.Handler {
	return h
}

func (h *recordingHandler) Records() []recordedLog {
	h.sink.mu.Lock()
	defer h.sink.mu.Unlock()

	records := make([]recordedLog, len(h.sink.records))
	copy(records, h.sink.records)

	return records
}

func recordStringAttr(attrs map[string]string, attr slog.Attr) {
	attrs[attr.Key] = fmt.Sprint(attr.Value.Any())
}

func hasLogRecord(records []recordedLog, level slog.Level, msg string, attrs map[string]string) bool {
	for _, record := range records {
		if record.level != level || record.msg != msg {
			continue
		}

		matched := true
		for key, value := range attrs {
			if record.attrs[key] != value {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}

	return false
}
