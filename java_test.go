package kalkan

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestJavaConfigurationRejectsClasspathSeparator(t *testing.T) {
	jar := filepath.Join(t.TempDir(), "provider"+string(filepath.ListSeparator)+"extra.jar")
	_, err := openWithBackendFactory(t.Context(), []Option{WithJavaProvider(jar)}, func(config) (backend, error) {
		t.Error("ambiguous provider classpath reached library factory")
		return newNativeBackend(&fakeSDK{}), nil
	})
	if err == nil {
		t.Fatal("ambiguous provider classpath accepted")
	}
}

func TestJavaConfigurationRejectsAmbiguousBackend(t *testing.T) {
	jar := filepath.Join(t.TempDir(), "provider.jar")
	for name, options := range map[string][]Option{
		"two backends":                    {WithLibraryPath(testLibraryPath()), WithJavaProvider(jar)},
		"XML without provider":            {WithLibraryPath(testLibraryPath()), WithJavaXMLLibraries(jar)},
		"relative XML JAR":                {WithJavaProvider(jar), WithJavaXMLLibraries("adapter.jar")},
		"NUL XML JAR":                     {WithJavaProvider(jar), WithJavaXMLLibraries(jar + "\x00other")},
		"relative JAR":                    {WithJavaProvider("provider.jar")},
		"NUL launcher":                    {WithJavaProvider(jar), WithJavaExecutable("java\x00other")},
		"launcher without provider":       {WithLibraryPath(testLibraryPath()), WithJavaExecutable("java")},
		"revocation without provider":     {WithLibraryPath(testLibraryPath()), WithJavaRevocation(CertificateValidationNone, "")},
		"unspecified revocation mode":     {WithJavaProvider(jar), WithJavaRevocation(CertificateValidationUnspecified, "")},
		"unknown revocation mode":         {WithJavaProvider(jar), WithJavaRevocation(CertificateValidationMode(99), "")},
		"source with disabled revocation": {WithJavaProvider(jar), WithJavaRevocation(CertificateValidationNone, "https://example.com")},
		"unsupported URL scheme":          {WithJavaProvider(jar), WithJavaRevocation(CertificateValidationOCSP, "file:///tmp/ocsp")},
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			_, err := openWithBackendFactory(context.Background(), options, func(config) (backend, error) {
				called = true
				return newNativeBackend(&fakeSDK{}), nil
			})
			if !errors.Is(err, ErrInvalidInput) || called {
				t.Fatalf("Open = %v, factory called = %t", err, called)
			}
		})
	}
}
