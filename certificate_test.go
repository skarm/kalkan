package kalkan

import (
	"bytes"
	"context"
	"os"
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

func TestLoadKeyStorePreservesPath(t *testing.T) {
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

func TestLoadKeyStoreRejectsNUL(t *testing.T) {
	native := &fakeNative{
		loadKeyStoreFunc: func(storage ckalkan.Store, password, container, alias string) error {
			t.Error("LoadKeyStore called native with embedded NUL")
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

func TestLoadKeyStoreAcceptsCyrillicInput(t *testing.T) {
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

func TestLoadTrustedCertificateMapsSources(t *testing.T) {
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
			WithLibraryPath(testLibraryPath()),
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

	select {
	case <-initEntered:
	case err := <-done:
		if err != nil {
			t.Fatalf("Open returned before Init: %v", err)
		}
		t.Fatal("Open returned before Init")
	}
	copy(data, []byte("mutated!"))
	close(releaseInit)

	if err := <-done; err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if got := <-certSeen; string(got) != "mutated!" {
		t.Fatalf("trusted certificate data = %q, want caller data without cloning", got)
	}
}

func TestOpenRetainsOwnedTrustedCertificatesUntilClose(t *testing.T) {
	data := []byte("trusted certificate setup data")
	wantData := string(data)
	loads := 0
	native := &fakeNative{
		loadKeyStoreFunc: func(ckalkan.Store, string, string, string) error { return nil },
		loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
			loads++
			if string(cert) != wantData {
				t.Fatalf("trusted certificate data = %q, want setup data", cert)
			}

			return nil
		},
	}

	client, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath(testLibraryPath()),
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

	if loads != 1 {
		t.Fatalf("Open loaded the trusted certificate %d times, want 1", loads)
	}
	clear(data)
	if err := client.LoadKeyStore(context.Background(), KeyStore{Path: "/tmp/key.p12"}); err != nil {
		t.Fatalf("LoadKeyStore returned error: %v", err)
	}
	if loads != 2 {
		t.Fatalf("certificate loads after key-store change = %d, want 2", loads)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if client.trusted != nil {
		t.Fatal("Close retained trusted certificate buffers")
	}
}

func TestLoadTrustedCertificateRejectsMultipleSources(t *testing.T) {
	native := &fakeNative{
		loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
			t.Error("LoadTrustedCertificate called native buffer loader with both Path and Data")
			return nil
		},
		loadCertFileFunc: func(path string, certType ckalkan.CertType) error {
			t.Error("LoadTrustedCertificate called native file loader with both Path and Data")
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

func TestLoadTrustedCertificatePath(t *testing.T) {
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
				t.Error("LoadTrustedCertificate called native with embedded NUL")
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

func TestLoadKeyStoreDoesNotStatPath(t *testing.T) {
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

func TestLoadTrustedCertificateDoesNotStatPath(t *testing.T) {
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

func TestSetProxyValidatesAndCallsNative(t *testing.T) {
	native := &fakeNative{
		setProxyFunc: func(req ckalkan.ProxyRequest) error {
			wantFlags := ckalkan.ProxyOn | ckalkan.ProxyAuth
			if req.Flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", req.Flags, wantFlags)
			}
			if req.Address != "127.0.0.1" || req.Port != "3128" {
				t.Fatalf("proxy address/port = %q/%q", req.Address, req.Port)
			}
			if req.User != "user" || req.Password != "password" {
				t.Fatalf("proxy credentials = %q/%q", req.User, req.Password)
			}

			return nil
		},
	}
	client := &Client{library: native}

	err := client.SetProxy(context.Background(), Proxy{
		Enabled:  true,
		Address:  " 127.0.0.1 ",
		Port:     " 3128 ",
		User:     "user",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("SetProxy returned error: %v", err)
	}
}

func TestSetProxyRejectsInvalidProxyBeforeNativeCall(t *testing.T) {
	native := &fakeNative{
		setProxyFunc: func(ckalkan.ProxyRequest) error {
			t.Error("SetProxy called native for invalid proxy")
			return nil
		},
	}
	client := &Client{library: native}

	err := client.SetProxy(context.Background(), Proxy{Enabled: true, Port: "3128"})
	if err == nil || !strings.Contains(err.Error(), "proxy address is empty") {
		t.Fatalf("SetProxy error = %v, want proxy address validation", err)
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
			name:  "address with whitespace",
			proxy: Proxy{Enabled: true, Address: "proxy host", Port: "3128"},
			want:  "proxy address contains whitespace",
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
			cfg := defaultOpenConfig()
			cfg.libraryPath = testLibraryPath()
			cfg.proxy = &test.proxy
			err := cfg.validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("config.validate error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestXMLCertificateInputPreservesBytesOutsideSignatureIDs(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{
			"signature attributes only",
			`<root xmlns:ds="` + xmlnsDSig + `" Id="root"><ds:Signature Id="2" title="Id='1' >"/><other:Signature xmlns:other="urn:other" Id="1"/><ds:Signature ds:Id="kept" Id='1'/></root>`,
			`<root xmlns:ds="` + xmlnsDSig + `" Id="root"><ds:Signature  title="Id='1' >"/><other:Signature xmlns:other="urn:other" Id="1"/><ds:Signature ds:Id="kept" /></root>`,
		},
		{
			"default namespace and whitespace",
			"<Signature xmlns='" + xmlnsDSig + "'\nId\t=\r '5'\t title='>'></Signature>",
			"<Signature xmlns='" + xmlnsDSig + "'\n\t title='>'></Signature>",
		},
		{
			"DTD and unknown entity stay native input",
			`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY label "document">]><root>&label;<Signature xmlns="` + xmlnsDSig + `" Id="1"/></root>`,
			`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY label "document">]><root>&label;<Signature xmlns="` + xmlnsDSig + `" /></root>`,
		},
		{
			"legacy encoding payload preserved",
			"<?xml version='1.0' encoding='windows-1251'?><root>\xef\xf0\xe8\xe2\xe5\xf2<Signature xmlns='" + xmlnsDSig + "' Id='5'/></root>",
			"<?xml version='1.0' encoding='windows-1251'?><root>\xef\xf0\xe8\xe2\xe5\xf2<Signature xmlns='" + xmlnsDSig + "' /></root>",
		},
		{
			"no signatures",
			`<root Id="1"><child title="Id='2' >"/></root>`,
			`<root Id="1"><child title="Id='2' >"/></root>`,
		},
		{
			"legacy namespace prefixes remain distinct",
			"<?xml version='1.0' encoding='windows-1251'?><root><scope xmlns:\xe0='" + xmlnsDSig + "' xmlns:\xe1='urn:other'><\xe0:Signature Id='2'/><\xe1:Signature Id='keep'/><\xe0:Signature Id='1'/></scope></root>",
			"<?xml version='1.0' encoding='windows-1251'?><root><scope xmlns:\xe0='" + xmlnsDSig + "' xmlns:\xe1='urn:other'><\xe0:Signature /><\xe1:Signature Id='keep'/><\xe0:Signature /></scope></root>",
		},
		{
			"legacy other namespace is not modified",
			"<?xml version='1.0' encoding='windows-1251'?><root><scope xmlns:\xe1='urn:other' xmlns:\xe0='" + xmlnsDSig + "'><\xe1:Signature Id='keep'/><\xe0:Signature title='\xef > Id' Id='2'/></scope></root>",
			"<?xml version='1.0' encoding='windows-1251'?><root><scope xmlns:\xe1='urn:other' xmlns:\xe0='" + xmlnsDSig + "'><\xe1:Signature Id='keep'/><\xe0:Signature title='\xef > Id' /></scope></root>",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(tc.input)
			got := xmlCertificateInput(input)
			if string(got) != tc.want {
				t.Fatalf("extraction XML = %q, want %q", got, tc.want)
			}
			if !bytes.Equal(input, []byte(tc.input)) {
				t.Fatal("certificate extraction changed the caller's XML")
			}
		})
	}
}
