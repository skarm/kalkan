package kalkan

import (
	"context"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestValidateCertificateMapsOCSPRequest(t *testing.T) {
	checkTime := time.Unix(1_700_000_000, 0).UTC()
	native := &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			if string(req.Certificate) != "cert-pem" {
				t.Fatalf("certificate = %q, want cert-pem", req.Certificate)
			}
			if req.ValidationType != ckalkan.UseOCSP {
				t.Fatalf("validation type = %#x, want UseOCSP", req.ValidationType)
			}
			if req.ValidationPath != "http://ocsp.example.test" {
				t.Fatalf("revocation source = %q", req.ValidationPath)
			}
			if req.CheckTimeUnix != checkTime.Unix() {
				t.Fatalf("check time = %d, want %d", req.CheckTimeUnix, checkTime.Unix())
			}
			wantFlags := ckalkan.GetOCSPResponse | ckalkan.NoCheckCertTime
			if req.Flags != wantFlags {
				t.Fatalf("flags = %#x, want %#x", req.Flags, wantFlags)
			}
			return ckalkan.ValidateCertificateResult{
				Info:         "certificate ok",
				OCSPResponse: []byte("ocsp-response"),
			}, nil
		},
	}
	client := &Client{library: native}

	validation, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate:          Bytes([]byte("cert-pem")),
		Mode:                 CertificateValidationOCSP,
		RevocationSource:     "http://ocsp.example.test",
		CheckTime:            checkTime,
		ReturnOCSPResponse:   true,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("ValidateCertificate returned error: %v", err)
	}
	if validation.Info != "certificate ok" {
		t.Fatalf("validation info = %q", validation.Info)
	}
	if string(validation.OCSPResponse) != "ocsp-response" {
		t.Fatalf("OCSP response = %q", validation.OCSPResponse)
	}
}

func TestValidateCertificateDoesNotCopyOCSPResponse(t *testing.T) {
	nativeOCSP := []byte("ocsp-response")
	client := &Client{library: &fakeNative{
		validateCertificateFunc: func(ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			return ckalkan.ValidateCertificateResult{
				Info:         "certificate ok",
				OCSPResponse: nativeOCSP,
			}, nil
		},
	}}

	validation, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate:        DER([]byte("cert")),
		Mode:               CertificateValidationOCSP,
		ReturnOCSPResponse: true,
	})
	if err != nil {
		t.Fatalf("ValidateCertificate returned error: %v", err)
	}
	if !sameByteSliceBacking(validation.OCSPResponse, nativeOCSP) {
		t.Fatal("ValidateCertificate cloned native OCSP response")
	}
}

func TestValidateCertificateTrimsOCSPRevocationSource(t *testing.T) {
	native := &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			if req.ValidationPath != "http://ocsp.example.test/path" {
				t.Fatalf("revocation source = %q, want trimmed OCSP URL", req.ValidationPath)
			}
			return ckalkan.ValidateCertificateResult{Info: "ok"}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate:      Bytes([]byte("cert-pem")),
		Mode:             CertificateValidationOCSP,
		RevocationSource: " \thttp://ocsp.example.test/path\n",
	})
	if err != nil {
		t.Fatalf("ValidateCertificate returned error: %v", err)
	}
}

func TestValidateCertificateUsesConfiguredOCSPURL(t *testing.T) {
	const configuredOCSPURL = "http://ocsp.example.test/"

	native := &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			if req.ValidationPath != configuredOCSPURL {
				t.Fatalf("revocation source = %q, want configured OCSP URL", req.ValidationPath)
			}
			return ckalkan.ValidateCertificateResult{Info: "ok"}, nil
		},
	}
	client := &Client{library: native, config: runtimeConfig{ocspURL: configuredOCSPURL}}

	_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate: Bytes([]byte("cert-pem")),
		Mode:        CertificateValidationOCSP,
	})
	if err != nil {
		t.Fatalf("ValidateCertificate returned error: %v", err)
	}
}

func TestValidateCertificateDoesNotReloadDefaults(t *testing.T) {
	native := &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			if req.ValidationPath != "" {
				t.Fatalf("revocation source = %q, want existing runtime value without default reapply", req.ValidationPath)
			}

			return ckalkan.ValidateCertificateResult{Info: "ok"}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate: DER([]byte("cert")),
		Mode:        CertificateValidationOCSP,
	})
	if err != nil {
		t.Fatalf("ValidateCertificate returned error: %v", err)
	}
}

func TestValidateCertificateRejectsUnusedRevocationSource(t *testing.T) {
	native := &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			t.Fatal("ValidateCertificate called native with RevocationSource and CertificateValidationNone")
			return ckalkan.ValidateCertificateResult{}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate:      Bytes([]byte("cert")),
		Mode:             CertificateValidationNone,
		RevocationSource: "/tmp/crl",
	})
	if err == nil || !strings.Contains(err.Error(), "RevocationSource") {
		t.Fatalf("ValidateCertificate error = %v, want RevocationSource rejection", err)
	}
}

func TestValidateCertificateRejectsInvalidOCSPURL(t *testing.T) {
	native := &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			t.Fatal("ValidateCertificate called native with invalid OCSP RevocationSource")
			return ckalkan.ValidateCertificateResult{}, nil
		},
	}
	client := &Client{library: native}

	tests := []struct {
		name             string
		revocationSource string
		want             string
	}{
		{name: "unsupported scheme", revocationSource: "ftp://ocsp.example.test", want: "http or https"},
		{name: "internal whitespace", revocationSource: "http://ocsp.example.test/bad path", want: "whitespace"},
		{name: "malformed URL", revocationSource: "http://[::1", want: "invalid"},
		{name: "missing host", revocationSource: "http:///ocsp", want: "host is empty"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
				Certificate:      Bytes([]byte("cert")),
				Mode:             CertificateValidationOCSP,
				RevocationSource: test.revocationSource,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateCertificate error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateCertificateRequiresOCSPModeForResponse(t *testing.T) {
	tests := []struct {
		name string
		req  ValidateCertificateRequest
	}{
		{
			name: "none",
			req: ValidateCertificateRequest{
				Certificate:        Bytes([]byte("cert")),
				Mode:               CertificateValidationNone,
				ReturnOCSPResponse: true,
			},
		},
		{
			name: "crl",
			req: ValidateCertificateRequest{
				Certificate:        Bytes([]byte("cert")),
				Mode:               CertificateValidationCRL,
				RevocationSource:   "/tmp/cert.crl",
				ReturnOCSPResponse: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			native := &fakeNative{
				validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
					t.Fatal("ValidateCertificate called native with ReturnOCSPResponse outside OCSP mode")
					return ckalkan.ValidateCertificateResult{}, nil
				},
			}
			client := &Client{library: native}

			_, err := client.ValidateCertificate(context.Background(), test.req)
			if err == nil || !strings.Contains(err.Error(), "ReturnOCSPResponse requires OCSP certificate validation mode") {
				t.Fatalf("ValidateCertificate error = %v, want ReturnOCSPResponse mode rejection", err)
			}
		})
	}
}

func TestValidateCertificateCRLPath(t *testing.T) {
	t.Run("preserve CRL path whitespace", func(t *testing.T) {
		crlPath := writeTestFile(t, t.TempDir(), "cert.crl", []byte("crl"))
		crlPathWithWhitespace := " \t" + crlPath + "\n"
		native := &fakeNative{
			validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
				if req.ValidationPath != crlPathWithWhitespace {
					t.Fatalf("revocation source = %q, want preserved path %q", req.ValidationPath, crlPathWithWhitespace)
				}
				return ckalkan.ValidateCertificateResult{Info: "ok"}, nil
			},
		}
		client := &Client{library: native}

		_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
			Certificate:      Bytes([]byte("cert")),
			Mode:             CertificateValidationCRL,
			RevocationSource: crlPathWithWhitespace,
		})
		if err != nil {
			t.Fatalf("ValidateCertificate returned error: %v", err)
		}
	})

	t.Run("reject NUL", func(t *testing.T) {
		native := &fakeNative{
			validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
				t.Fatal("ValidateCertificate called native with embedded NUL RevocationSource")
				return ckalkan.ValidateCertificateResult{}, nil
			},
		}
		client := &Client{library: native}

		_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
			Certificate:      Bytes([]byte("cert")),
			Mode:             CertificateValidationCRL,
			RevocationSource: "/tmp/cert\x00.crl",
		})
		if err == nil || !strings.Contains(err.Error(), "NUL") {
			t.Fatalf("ValidateCertificate error = %v, want embedded NUL error", err)
		}
	})
}

func TestValidateCertificateDoesNotStatCRLPath(t *testing.T) {
	dir := t.TempDir()
	target := writeTestFile(t, dir, "target.crl", []byte("crl"))
	link := target + ".link"
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink is unavailable: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{name: "file", path: writeTestFile(t, t.TempDir(), "cert.crl", []byte("crl"))},
		{name: "directory", path: t.TempDir()},
		{name: "symlink", path: link},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			native := &fakeNative{
				validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
					if req.ValidationPath != test.path {
						t.Fatalf("RevocationSource = %q, want %q", req.ValidationPath, test.path)
					}

					return ckalkan.ValidateCertificateResult{Info: "ok"}, nil
				},
			}
			client := &Client{library: native}

			_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
				Certificate:      Bytes([]byte("cert")),
				Mode:             CertificateValidationCRL,
				RevocationSource: test.path,
			})
			if err != nil {
				t.Fatalf("ValidateCertificate returned error: %v", err)
			}
		})
	}
}

func TestValidateCertificateOnNilClient(t *testing.T) {
	var client *Client

	_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate: Bytes([]byte("cert")),
		Mode:        CertificateValidationOCSP,
	})
	if err == nil || !strings.Contains(err.Error(), "client is closed") {
		t.Fatalf("ValidateCertificate nil client error = %v, want closed client error", err)
	}
}

func TestValidateCertificateRequiresMode(t *testing.T) {
	native := &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			t.Fatal("ValidateCertificate called native X509ValidateCertificate for unspecified validation mode")
			return ckalkan.ValidateCertificateResult{}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate: Bytes([]byte("cert-pem")),
	})
	if err == nil || !strings.Contains(err.Error(), "certificate validation mode is required") {
		t.Fatalf("ValidateCertificate error = %v, want required mode error", err)
	}
}

func TestValidateCertificateRejectsEmptyCertificate(t *testing.T) {
	native := &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			t.Fatal("ValidateCertificate called native X509ValidateCertificate for empty certificate")
			return ckalkan.ValidateCertificateResult{}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate: Bytes(nil),
		Mode:        CertificateValidationNone,
	})
	if err == nil || !strings.Contains(err.Error(), "certificate is empty") {
		t.Fatalf("ValidateCertificate error = %v, want empty certificate error", err)
	}
}

func TestValidateCertificateRejectsInvalidPEM(t *testing.T) {
	validCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("cert-der")})

	tests := []struct {
		name string
		pem  []byte
		want string
	}{
		{
			name: "non-certificate block",
			pem:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("cert-der")}),
			want: "CERTIFICATE",
		},
		{
			name: "trailing non-whitespace",
			pem:  append(append([]byte{}, validCert...), []byte("trailing")...),
			want: "trailing data",
		},
		{
			name: "leading non-whitespace",
			pem:  append([]byte("leading\n"), validCert...),
			want: "leading data",
		},
		{
			name: "second PEM block",
			pem:  append(append([]byte{}, validCert...), validCert...),
			want: "multiple PEM blocks",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			native := &fakeNative{
				validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
					t.Fatal("ValidateCertificate called native with invalid PEM")
					return ckalkan.ValidateCertificateResult{}, nil
				},
			}
			client := &Client{library: native}

			_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
				Certificate: PEM(test.pem),
				Mode:        CertificateValidationNone,
			})
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateCertificate error = %v, want ErrInvalidInput containing %q", err, test.want)
			}
		})
	}
}

func TestCertificateInputRejectsEmptyDER(t *testing.T) {
	tests := []struct {
		name   string
		source Source
	}{
		{
			name:   "PEM",
			source: PEM([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----")),
		},
		{
			name:   "base64",
			source: Base64([]byte(" \n\t")),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := certificateValidationInput(test.source, 0)
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "decodes to empty DER") {
				t.Fatalf("certificateValidationInput error = %v, want empty decoded DER rejection", err)
			}
		})
	}
}

func TestValidateCertificateAcceptsNoRevocation(t *testing.T) {
	native := &fakeNative{
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			if req.ValidationType != ckalkan.UseNothing {
				t.Fatalf("validation type = %#x, want UseNothing", req.ValidationType)
			}
			return ckalkan.ValidateCertificateResult{Info: "ok"}, nil
		},
	}
	client := &Client{library: native}

	_, err := client.ValidateCertificate(context.Background(), ValidateCertificateRequest{
		Certificate: Bytes([]byte("cert-pem")),
		Mode:        CertificateValidationNone,
	})
	if err != nil {
		t.Fatalf("ValidateCertificate returned error: %v", err)
	}
}

func TestValidationErrorsWrapErrInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "empty file source path",
			run: func() error {
				_, err := validateNativePathString("file source path", "")
				return err
			},
		},
		{
			name: "unknown encoding",
			run: func() error {
				return validateEncoding(Encoding(99))
			},
		},
		{
			name: "missing hash input",
			run: func() error {
				_, err := (*Client)(nil).Hash(context.Background(), HashRequest{})
				return err
			},
		},
		{
			name: "empty digest input",
			run: func() error {
				_, err := (*Client)(nil).SignHash(context.Background(), SignHashRequest{})
				return err
			},
		},
		{
			name: "unknown hash algorithm",
			run: func() error {
				_, err := HashAlgorithm(99).native()
				return err
			},
		},
		{
			name: "missing CMS input",
			run: func() error {
				_, err := (*Client)(nil).SignCMS(context.Background(), SignCMSRequest{})
				return err
			},
		},
		{
			name: "detached CMS data without detached mode",
			run: func() error {
				_, err := (*Client)(nil).VerifyCMS(context.Background(), VerifyCMSRequest{Data: Bytes([]byte("data"))})
				return err
			},
		},
		{
			name: "missing CMS signature",
			run: func() error {
				_, _, err := cmsSignatureInput(Source{}, EncodingAuto, 0)
				return err
			},
		},
		{
			name: "unsupported detached CMS data encoding",
			run: func() error {
				_, _, err := cmsDataInput(DER([]byte("data")), 0)
				return err
			},
		},
		{
			name: "unknown CMS output format",
			run: func() error {
				_, err := cmsOutputFlag(CMSOutputFormat(99))
				return err
			},
		},
		{
			name: "unknown certificate time check",
			run: func() error {
				_, err := certificateTimeCheckFlag(CertificateTimeCheck(99))
				return err
			},
		},
		{
			name: "invalid WSSE body ID",
			run: func() error {
				return validateSOAPBodyID("")
			},
		},
		{
			name: "invalid WSSE payload",
			run: func() error {
				return validateSingleXMLElement(nil)
			},
		},
		{
			name: "missing XML source",
			run: func() error {
				_, err := xmlInput(Source{}, 0)
				return err
			},
		},
		{
			name: "unsupported XML source encoding",
			run: func() error {
				_, err := xmlInput(PEM([]byte("<root/>")), 0)
				return err
			},
		},
		{
			name: "unknown XML canonicalization",
			run: func() error {
				_, err := xmlCanonicalizationFlag(XMLCanonicalization(99))
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}
