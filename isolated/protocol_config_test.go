package isolated

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/kalkan"
)

func TestLibraryConfigRoundTripPreservesAllOpaqueStrings(t *testing.T) {
	tsa, ocsp := "http://tsa/\xff", "http://ocsp/\xfe"
	want := libraryConfig{
		CollectObservations: true, LibraryPath: "/library/\xfd", TSAURL: &tsa, OCSPURL: &ocsp,
		Proxy: &kalkan.Proxy{Enabled: true, Address: "addr\xfc", Port: "port\xfb", User: "user\xfa", Password: "secret\xf9"},
		TrustedCertificates: []kalkan.TrustedCertificate{
			{Path: "/cert\xf8", Type: kalkan.CertificateCA},
			{Data: []byte{0, 0xff, 2}, Type: kalkan.CertificateIntermediate, Format: kalkan.CertificatePEM},
		},
		MaxInputSize: 17, MaxOutputBufferSize: 19, AtomicZIPOutput: true,
		EndpointPolicy: &kalkan.EndpointPolicy{AllowedHosts: []string{"host\xf7"}, AllowedPorts: []string{"port\xf6"}, RequireHTTPS: true, AllowIPAddresses: true},
	}
	got := roundTripConfig(t, want)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("wire configuration did not preserve every field and opaque string byte")
	}
}

func TestLibraryConfigRoundTripPreservesAbsentAndExplicitEmptyOptions(t *testing.T) {
	empty := ""
	for _, want := range []libraryConfig{
		{},
		{TSAURL: &empty, OCSPURL: &empty, Proxy: &kalkan.Proxy{}, TrustedCertificates: []kalkan.TrustedCertificate{}, EndpointPolicy: &kalkan.EndpointPolicy{AllowedHosts: []string{}}},
	} {
		got := roundTripConfig(t, want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("wire configuration = %#v, want %#v", got, want)
		}
	}
}

func TestLibraryConfigOptionsDelegateValidationToRoot(t *testing.T) {
	empty := ""
	for _, test := range []struct {
		name       string
		config     libraryConfig
		diagnostic string
	}{
		{"explicit empty TSA URL", libraryConfig{TSAURL: &empty}, "TSA URL"},
		{"invalid output limit", libraryConfig{MaxOutputBufferSize: -1}, "maximum output buffer size"},
		{"empty endpoint policy", libraryConfig{EndpointPolicy: &kalkan.EndpointPolicy{}}, "endpoint policy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := test.config
			config.LibraryPath = filepath.Join(t.TempDir(), "library.so")
			config = roundTripConfig(t, config)
			client, err := kalkan.Open(context.Background(), config.Options()...)
			if client != nil {
				_ = client.Close()
				t.Fatal("Open unexpectedly reached a usable library for invalid configuration")
			}
			if !errors.Is(err, kalkan.ErrInvalidInput) || !strings.Contains(err.Error(), test.diagnostic) {
				t.Fatalf("root Open = %v, want root validation for %q", err, test.diagnostic)
			}
		})
	}
}

func roundTripConfig(t *testing.T, config libraryConfig) libraryConfig {
	t.Helper()
	data, err := encodeConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeConfig(roundTripPayload(t, data))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
