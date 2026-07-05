package kalkan

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestLoadKeyStoreValidatesTypeAndPath(t *testing.T) {
	client := &Client{library: &fakeNative{}}

	err := client.LoadKeyStore(context.Background(), KeyStore{
		Type: KeyStoreType(99),
		Path: "/tmp/key.p12",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown key store type") {
		t.Fatalf("LoadKeyStore unknown type error = %v", err)
	}

	err = client.LoadKeyStore(context.Background(), KeyStore{
		Type: PKCS12,
	})
	if err == nil || !strings.Contains(err.Error(), "key store path is empty") {
		t.Fatalf("LoadKeyStore empty path error = %v", err)
	}
}

func TestLoadKeyStorePreservesPathWhitespaceBeforeNativeCall(t *testing.T) {
	path := writeTestFile(t, t.TempDir(), "key.p12", []byte("p12"))
	pathWithWhitespace := " \t" + path + "\n"
	native := &fakeNative{
		loadKeyStoreFunc: func(storage ckalkan.Store, password, container, alias string) error {
			if container != pathWithWhitespace {
				t.Fatalf("container = %q, want preserved path %q", container, pathWithWhitespace)
			}
			return nil
		},
	}
	client := &Client{library: native}

	err := client.LoadKeyStore(context.Background(), KeyStore{
		Type: PKCS12,
		Path: pathWithWhitespace,
	})
	if err != nil {
		t.Fatalf("LoadKeyStore returned error: %v", err)
	}
}

func TestLoadKeyStoreRejectsEmbeddedNULBeforeNativeCall(t *testing.T) {
	native := &fakeNative{
		loadKeyStoreFunc: func(storage ckalkan.Store, password, container, alias string) error {
			t.Fatal("LoadKeyStore called native with embedded NUL")
			return nil
		},
	}
	client := &Client{library: native}

	err := client.LoadKeyStore(context.Background(), KeyStore{
		Type:     PKCS12,
		Path:     "/tmp/key.p12",
		Password: "bad\x00password",
	})
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("LoadKeyStore error = %v, want embedded NUL error", err)
	}
}

func TestLoadKeyStorePassesPKCS12ToNative(t *testing.T) {
	path := writeTestFile(t, t.TempDir(), "key.p12", []byte("p12"))
	native := &fakeNative{
		loadKeyStoreFunc: func(storage ckalkan.Store, password, container, alias string) error {
			if storage != ckalkan.StorePKCS12 {
				t.Fatalf("storage = %#x, want StorePKCS12", storage)
			}
			if password != "secret" {
				t.Fatalf("password = %q", password)
			}
			if container != path {
				t.Fatalf("container = %q", container)
			}
			if alias != "alias" {
				t.Fatalf("alias = %q", alias)
			}
			return nil
		},
	}
	client := &Client{library: native}

	err := client.LoadKeyStore(context.Background(), KeyStore{
		Type:     PKCS12,
		Path:     path,
		Password: "secret",
		Alias:    "alias",
	})
	if err != nil {
		t.Fatalf("LoadKeyStore returned error: %v", err)
	}
}

func TestLoadKeyStoreAllowsCyrillicPathPasswordAndAlias(t *testing.T) {
	path := writeTestFile(t, t.TempDir(), "ключ.p12", []byte("p12"))
	native := &fakeNative{
		loadKeyStoreFunc: func(storage ckalkan.Store, password, container, alias string) error {
			if container != path {
				t.Fatalf("container = %q", container)
			}
			if password != "пароль" {
				t.Fatalf("password = %q", password)
			}
			if alias != "алиас" {
				t.Fatalf("alias = %q", alias)
			}
			return nil
		},
	}
	client := &Client{library: native}

	err := client.LoadKeyStore(context.Background(), KeyStore{
		Type:     PKCS12,
		Path:     path,
		Password: "пароль",
		Alias:    "алиас",
	})
	if err != nil {
		t.Fatalf("LoadKeyStore returned error: %v", err)
	}
}

func TestLoadTrustedCertificatePassesBufferAndFileToNative(t *testing.T) {
	certPath := writeTestFile(t, t.TempDir(), "ca.pem", []byte("cert"))
	bufferLoaded := false
	fileLoaded := false
	native := &fakeNative{
		loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
			bufferLoaded = true
			if string(cert) != "cert-pem" {
				t.Fatalf("cert = %q", cert)
			}
			if format != ckalkan.CertPEM {
				t.Fatalf("format = %#x, want CertPEM", format)
			}
			return nil
		},
		loadCertFileFunc: func(path string, certType ckalkan.CertType) error {
			fileLoaded = true
			if path != certPath {
				t.Fatalf("path = %q", path)
			}
			if certType != ckalkan.CertCA {
				t.Fatalf("cert type = %#x, want CertCA", certType)
			}
			return nil
		},
	}
	client := &Client{library: native}

	if err := client.LoadTrustedCertificate(context.Background(), TrustedCertificate{
		Data:   []byte("cert-pem"),
		Type:   CertificateUser,
		Format: CertificatePEM,
	}); err != nil {
		t.Fatalf("LoadTrustedCertificate(buffer) returned error: %v", err)
	}
	if err := client.LoadTrustedCertificate(context.Background(), TrustedCertificate{
		Path: certPath,
		Type: CertificateCA,
	}); err != nil {
		t.Fatalf("LoadTrustedCertificate(file) returned error: %v", err)
	}
	if !bufferLoaded || !fileLoaded {
		t.Fatalf("loaded buffer=%v file=%v, want both", bufferLoaded, fileLoaded)
	}
}

func TestLoadTrustedCertificateUsesCallerData(t *testing.T) {
	data := []byte("original")
	enteredNative := make(chan struct{})
	releaseNative := make(chan struct{})
	certSeen := make(chan []byte, 1)

	native := &fakeNative{
		loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
			close(enteredNative)
			<-releaseNative
			certSeen <- append([]byte(nil), cert...)
			return nil
		},
	}
	client := &Client{library: native}

	done := make(chan error, 1)
	go func() {
		done <- client.LoadTrustedCertificate(context.Background(), TrustedCertificate{
			Data:   data,
			Type:   CertificateCA,
			Format: CertificatePEM,
		})
	}()

	<-enteredNative
	copy(data, []byte("mutated!"))
	close(releaseNative)

	if err := <-done; err != nil {
		t.Fatalf("LoadTrustedCertificate returned error: %v", err)
	}
	if got := <-certSeen; string(got) != "mutated!" {
		t.Fatalf("certificate data = %q, want caller data without cloning", got)
	}
}

func TestOpenWithTrustedCertificateUsesCallerData(t *testing.T) {
	data := []byte("original")
	initEntered := make(chan struct{})
	releaseInit := make(chan struct{})
	certSeen := make(chan []byte, 1)
	native := &fakeNative{
		initFunc: func() error {
			close(initEntered)
			<-releaseInit
			return nil
		},
		loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
			certSeen <- append([]byte(nil), cert...)
			return nil
		},
	}

	done := make(chan error, 1)
	go func() {
		client, err := openWithLibraryFactory(context.Background(), []Option{
			WithLibraryPath("/opt/kalkan/libkalkancryptwr-64.so"),
			WithTrustedCertificate(TrustedCertificate{
				Data:   data,
				Type:   CertificateCA,
				Format: CertificatePEM,
			}),
		}, func(config) (closer, error) {
			return native, nil
		})
		if client != nil {
			_ = client.Close()
		}
		done <- err
	}()

	<-initEntered
	copy(data, []byte("mutated!"))
	close(releaseInit)

	if err := <-done; err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if got := <-certSeen; string(got) != "mutated!" {
		t.Fatalf("trusted certificate data = %q, want caller data without cloning", got)
	}
}

func TestOpenDoesNotRetainTrustedCertificatesAfterSetup(t *testing.T) {
	data := []byte("trusted certificate setup data")
	var loaded bool
	native := &fakeNative{
		loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
			loaded = true
			if string(cert) != string(data) {
				t.Fatalf("trusted certificate data = %q, want setup data", cert)
			}

			return nil
		},
	}

	client, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath("/opt/kalkan/libkalkancryptwr-64.so"),
		WithTrustedCertificate(TrustedCertificate{
			Data:   data,
			Type:   CertificateCA,
			Format: CertificatePEM,
		}),
	}, func(config) (closer, error) {
		return native, nil
	})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	}()

	if !loaded {
		t.Fatal("Open did not load trusted certificate during setup")
	}
	if _, ok := reflect.TypeOf(client.config).FieldByName("trusted"); ok {
		t.Fatal("Client runtime config retained trusted certificates after setup")
	}
	if _, ok := reflect.TypeOf(client.config).FieldByName("libraryPath"); ok {
		t.Fatal("Client runtime config retained setup-only library path after setup")
	}
}

func TestLoadTrustedCertificateRejectsPathAndDataTogetherBeforeNativeCall(t *testing.T) {
	native := &fakeNative{
		loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
			t.Fatal("LoadTrustedCertificate called native buffer loader with both Path and Data")
			return nil
		},
		loadCertFileFunc: func(path string, certType ckalkan.CertType) error {
			t.Fatal("LoadTrustedCertificate called native file loader with both Path and Data")
			return nil
		},
	}
	client := &Client{library: native}

	err := client.LoadTrustedCertificate(context.Background(), TrustedCertificate{
		Data:   []byte("cert"),
		Path:   "/tmp/ca.pem",
		Type:   CertificateCA,
		Format: CertificatePEM,
	})
	if err == nil || !strings.Contains(err.Error(), "either Path or Data") {
		t.Fatalf("LoadTrustedCertificate error = %v, want Path/Data conflict error", err)
	}
}

func TestLoadTrustedCertificatePreservesPathWhitespaceAndRejectsEmbeddedNUL(t *testing.T) {
	t.Run("preserve path whitespace", func(t *testing.T) {
		certPath := writeTestFile(t, t.TempDir(), "ca.pem", []byte("cert"))
		certPathWithWhitespace := " \n" + certPath + "\t"
		native := &fakeNative{
			loadCertFileFunc: func(path string, certType ckalkan.CertType) error {
				if path != certPathWithWhitespace {
					t.Fatalf("path = %q, want preserved path %q", path, certPathWithWhitespace)
				}
				return nil
			},
		}
		client := &Client{library: native}

		err := client.LoadTrustedCertificate(context.Background(), TrustedCertificate{
			Path: certPathWithWhitespace,
			Type: CertificateCA,
		})
		if err != nil {
			t.Fatalf("LoadTrustedCertificate returned error: %v", err)
		}
	})

	t.Run("reject NUL", func(t *testing.T) {
		native := &fakeNative{
			loadCertFileFunc: func(path string, certType ckalkan.CertType) error {
				t.Fatal("LoadTrustedCertificate called native with embedded NUL")
				return nil
			},
		}
		client := &Client{library: native}

		err := client.LoadTrustedCertificate(context.Background(), TrustedCertificate{
			Path: "/tmp/ca\x00.pem",
			Type: CertificateCA,
		})
		if err == nil || !strings.Contains(err.Error(), "NUL") {
			t.Fatalf("LoadTrustedCertificate error = %v, want embedded NUL error", err)
		}
	})
}

func TestLoadKeyStorePassesPathToNativeWithoutRegularFilePreflight(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		assertLoadKeyStoreReceivesPath(t, t.TempDir())
	})

	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := writeTestFile(t, dir, "key.p12", []byte("p12"))
		link := target + ".link"
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink is unavailable: %v", err)
		}

		assertLoadKeyStoreReceivesPath(t, link)
	})
}

func TestLoadTrustedCertificatePassesPathToNativeWithoutRegularFilePreflight(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		assertLoadTrustedCertificateReceivesPath(t, t.TempDir())
	})

	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := writeTestFile(t, dir, "ca.pem", []byte("cert"))
		link := target + ".link"
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink is unavailable: %v", err)
		}

		assertLoadTrustedCertificateReceivesPath(t, link)
	})
}

func assertLoadKeyStoreReceivesPath(t *testing.T, path string) {
	t.Helper()

	native := &fakeNative{
		loadKeyStoreFunc: func(storage ckalkan.Store, password, container, alias string) error {
			if container != path {
				t.Fatalf("container = %q, want %q", container, path)
			}
			return nil
		},
	}
	client := &Client{library: native}

	err := client.LoadKeyStore(context.Background(), KeyStore{
		Type: PKCS12,
		Path: path,
	})
	if err != nil {
		t.Fatalf("LoadKeyStore returned error: %v", err)
	}
}

func assertLoadTrustedCertificateReceivesPath(t *testing.T, path string) {
	t.Helper()

	native := &fakeNative{
		loadCertFileFunc: func(got string, certType ckalkan.CertType) error {
			if got != path {
				t.Fatalf("path = %q, want %q", got, path)
			}
			return nil
		},
	}
	client := &Client{library: native}

	err := client.LoadTrustedCertificate(context.Background(), TrustedCertificate{
		Path: path,
		Type: CertificateCA,
	})
	if err != nil {
		t.Fatalf("LoadTrustedCertificate returned error: %v", err)
	}
}

func TestProxyNativeFlags(t *testing.T) {
	disabledWithCredentials := Proxy{
		Address:  "127.0.0.1",
		Port:     "3128",
		User:     "proxy-user",
		Password: "proxy-password",
	}.native()
	if disabledWithCredentials.Flags != ckalkan.ProxyOff {
		t.Fatalf("disabled proxy flags = %#x, want ProxyOff", disabledWithCredentials.Flags)
	}
	if disabledWithCredentials.Address != "" || disabledWithCredentials.Port != "" ||
		disabledWithCredentials.User != "" || disabledWithCredentials.Password != "" {
		t.Fatalf("disabled proxy leaked native settings: %+v", disabledWithCredentials)
	}

	enabledWithCredentials := Proxy{
		Enabled:  true,
		Address:  " 127.0.0.1 ",
		Port:     " 3128 ",
		User:     "proxy-user",
		Password: "proxy-password",
	}.native()
	wantFlags := ckalkan.ProxyOn | ckalkan.ProxyAuth
	if enabledWithCredentials.Flags != wantFlags {
		t.Fatalf("enabled proxy flags = %#x, want %#x", enabledWithCredentials.Flags, wantFlags)
	}
	if enabledWithCredentials.Address != "127.0.0.1" || enabledWithCredentials.Port != "3128" {
		t.Fatalf("enabled proxy address/port = %q/%q, want trimmed values", enabledWithCredentials.Address, enabledWithCredentials.Port)
	}
}

func TestConfigValidateRejectsInvalidEnabledProxy(t *testing.T) {
	tests := []struct {
		name  string
		proxy Proxy
		want  string
	}{
		{
			name:  "missing address",
			proxy: Proxy{Enabled: true, Port: "3128"},
			want:  "proxy address is empty",
		},
		{
			name:  "missing port",
			proxy: Proxy{Enabled: true, Address: "127.0.0.1"},
			want:  "proxy port is empty",
		},
		{
			name:  "non numeric port",
			proxy: Proxy{Enabled: true, Address: "127.0.0.1", Port: "https"},
			want:  "proxy port must be a number",
		},
		{
			name:  "zero port",
			proxy: Proxy{Enabled: true, Address: "127.0.0.1", Port: "0"},
			want:  "proxy port must be in range",
		},
		{
			name:  "too large port",
			proxy: Proxy{Enabled: true, Address: "127.0.0.1", Port: "65536"},
			want:  "proxy port must be in range",
		},
		{
			name:  "address with NUL",
			proxy: Proxy{Enabled: true, Address: "127.0.0.1\x00", Port: "3128"},
			want:  "NUL",
		},
		{
			name:  "port with NUL",
			proxy: Proxy{Enabled: true, Address: "127.0.0.1", Port: "3128\x00"},
			want:  "NUL",
		},
		{
			name:  "user with NUL",
			proxy: Proxy{Enabled: true, Address: "127.0.0.1", Port: "3128", User: "bad\x00user"},
			want:  "NUL",
		},
		{
			name:  "password with NUL",
			proxy: Proxy{Enabled: true, Address: "127.0.0.1", Port: "3128", Password: "bad\x00password"},
			want:  "NUL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := config{
				libraryPath: "/opt/kalkan/libkalkancryptwr-64.so",
				proxy:       &test.proxy,
			}
			err := cfg.validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("config.validate error = %v, want %q", err, test.want)
			}
		})
	}
}
