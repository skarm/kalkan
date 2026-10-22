package ckalkan_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ckalkan "github.com/skarm/kalkan/ckalkan"
)

func TestCMSFixtures(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newIntegrationClient(t, largeBufferOptions()...)
	loadCertificates(t, client, assets)

	t.Run("attached timestamped CMS", func(t *testing.T) {
		cms := readExample(t, assets, "test_CMS_GOST")
		verified, err := client.VerifyData(ckalkan.VerifyDataRequest{
			Flags:              ckalkan.SignCMS | ckalkan.InPEM | ckalkan.NoCheckCertTime,
			Signature:          cms,
			VerifyInfoCapacity: 1 << 20,
			DataCapacity:       1 << 20,
			CertCapacity:       1 << 20,
		})
		if err != nil {
			t.Fatalf("VerifyData(CMS fixture) failed: %v", err)
		}
		requireStringContains(t, "CMS fixture verify info", verified.VerifyInfo, "Verify - OK")
		requireStringContains(t, "CMS fixture verify info", verified.VerifyInfo, "CAdES-T")
		if len(verified.Data) == 0 {
			t.Fatal("VerifyData(CMS fixture) returned empty attached data")
		}

		cert, err := client.GetCertFromCMS(cms, 1, ckalkan.InPEM|ckalkan.OutDER)
		if err != nil {
			t.Fatalf("GetCertFromCMS(CMS fixture) failed: %v", err)
		}
		if _, err := x509.ParseCertificate(cert); err != nil {
			t.Fatalf("GetCertFromCMS returned invalid signer certificate: %v", err)
		}
		if _, err := client.GetTimeFromSig(cms, ckalkan.InPEM|ckalkan.NoCheckCertTime, 0); err == nil {
			t.Fatal("GetTimeFromSig(CMS fixture) unexpectedly succeeded for expired CMS fixture fixture")
		} else {
			_ = requireKalkanError(t, "GetTimeFromSig(CMS fixture)", err)
		}
	})

	t.Run("detached CMS without data", func(t *testing.T) {
		cms := readExample(t, assets, "CMS_for_double_sign")
		cert, err := client.GetCertFromCMS(cms, 1, ckalkan.InPEM|ckalkan.OutDER)
		if err != nil {
			t.Fatalf("GetCertFromCMS(CMS_for_double_sign) failed: %v", err)
		}
		if _, err := x509.ParseCertificate(cert); err != nil {
			t.Fatalf("GetCertFromCMS returned invalid signer certificate: %v", err)
		}
		if _, err := client.GetTimeFromSig(cms, ckalkan.InPEM|ckalkan.NoCheckCertTime, 0); err == nil {
			t.Fatal("GetTimeFromSig(CMS_for_double_sign) unexpectedly found a timestamp")
		} else if kalkanErr := requireKalkanError(t, "GetTimeFromSig(CMS_for_double_sign)", err); kalkanErr.Code != ckalkan.ErrorNoTSAToken {
			t.Fatalf("GetTimeFromSig(CMS_for_double_sign) code = %v, want ErrorNoTSAToken", kalkanErr.Code)
		}
		if _, err := client.VerifyData(ckalkan.VerifyDataRequest{
			Flags:              ckalkan.SignCMS | ckalkan.InPEM | ckalkan.NoCheckCertTime,
			Signature:          cms,
			VerifyInfoCapacity: 1 << 20,
			DataCapacity:       1 << 20,
			CertCapacity:       1 << 20,
		}); err == nil {
			t.Fatal("VerifyData(CMS_for_double_sign without detached data) unexpectedly succeeded")
		} else {
			_ = requireKalkanError(t, "VerifyData(CMS_for_double_sign without detached data)", err)
		}
	})
}

func TestSignVerifyVariants(t *testing.T) {
	assets := loadFixtureAssets(t)
	client := newIntegrationClient(t, largeBufferOptions()...)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixturePassword, chooseStore(t, assets.P12), ""); err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}

	if err := client.SetProxy(ckalkan.ProxyRequest{Flags: ckalkan.ProxyOff}); err != nil {
		t.Fatalf("SetProxy(ProxyOff) failed: %v", err)
	}
	if err := client.SetTSAURL("http://test.pki.gov.kz/tsp/"); err != nil {
		t.Fatalf("SetTSAURL failed: %v", err)
	}

	data := readExample(t, assets, "text")
	if len(bytes.TrimSpace(data)) == 0 {
		data = []byte("ckalkan CMS fixture data")
	}

	variants := []struct {
		name        string
		signFlags   ckalkan.Flag
		verifyFlags ckalkan.Flag
		wantData    bool
	}{
		{name: "attached base64 CMS", signFlags: ckalkan.SignCMS | ckalkan.OutBase64 | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.NoCheckCertTime, wantData: true},
		{name: "attached DER CMS", signFlags: ckalkan.SignCMS | ckalkan.OutDER | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime, wantData: true},
		{name: "attached PEM CMS", signFlags: ckalkan.SignCMS | ckalkan.OutPEM | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignCMS | ckalkan.InPEM | ckalkan.NoCheckCertTime, wantData: true},
		{name: "detached base64 CMS", signFlags: ckalkan.SignCMS | ckalkan.OutBase64 | ckalkan.DetachedData | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.DetachedData | ckalkan.NoCheckCertTime},
		{name: "detached DER CMS", signFlags: ckalkan.SignCMS | ckalkan.OutDER | ckalkan.DetachedData | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.DetachedData | ckalkan.NoCheckCertTime},
		{name: "draft base64", signFlags: ckalkan.SignDraft | ckalkan.OutBase64 | ckalkan.NoCheckCertTime, verifyFlags: ckalkan.SignDraft | ckalkan.InBase64 | ckalkan.NoCheckCertTime},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			sig, err := client.SignData(ckalkan.SignDataRequest{Flags: variant.signFlags, Data: data})
			if err != nil {
				t.Fatalf("SignData failed: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("SignData returned empty data")
			}
			verified, err := client.VerifyData(ckalkan.VerifyDataRequest{
				Flags:              variant.verifyFlags,
				Data:               data,
				Signature:          sig,
				VerifyInfoCapacity: 1 << 20,
				DataCapacity:       1 << 20,
				CertCapacity:       1 << 20,
			})
			if err != nil {
				t.Fatalf("VerifyData failed: %v", err)
			}
			requireStringContains(t, "verify info", verified.VerifyInfo, "Verify - OK")
			if variant.wantData && !bytes.Equal(verified.Data, data) {
				t.Fatalf("VerifyData returned data %q, want %q", verified.Data, data)
			}
		})
	}

	gost512Digest := make([]byte, 64)
	for i := range gost512Digest {
		gost512Digest[i] = byte(i)
	}
	for _, flags := range []ckalkan.Flag{
		ckalkan.SignCMS | ckalkan.OutBase64 | ckalkan.NoCheckCertTime,
		ckalkan.SignCMS | ckalkan.OutDER | ckalkan.NoCheckCertTime,
		ckalkan.SignDraft | ckalkan.OutBase64 | ckalkan.NoCheckCertTime,
	} {
		sig, err := client.SignHash("", flags, gost512Digest)
		if err != nil {
			t.Fatalf("SignHash(%#x) failed: %v", flags, err)
		}
		if len(sig) == 0 {
			t.Fatalf("SignHash(%#x) returned empty data", flags)
		}
	}
}

// TestCMSVerificationMatrix verifies CMS formats and rejects changed signatures
// or payloads.
//
// Every negative case starts from a positive control with a verified
// cryptographic signature. Signature mutations preserve CMS structure. Payload
// mutations preserve length.
func TestCMSVerificationMatrix(t *testing.T) {
	client := newIntegrationClient(t)
	rsa := generatePKCS12Fixture(t)
	assets := loadFixtureAssets(t)
	payload := []byte("CMS matrix: Кириллица\x00\xff\r\ncontent must be authenticated")
	for _, profile := range []struct {
		name, store, password string
		hash                  ckalkan.HashAlgorithm
		flags                 ckalkan.Flag
	}{
		// A synthetic self-signed RSA identity has no NCA trust chain.
		// This matrix checks signature integrity.
		// Separate tests cover chain and time rejection.
		{"RSA", rsa.P12Path, rsa.Password, ckalkan.SHA256, ckalkan.NoCheckCertTime},
		{"GOST512", chooseStore(t, assets.P12), fixturePassword, ckalkan.GOST2015_512, ckalkan.NoCheckCertTime},
	} {
		t.Run(profile.name, func(t *testing.T) {
			if err := client.LoadKeyStore(ckalkan.StorePKCS12, profile.password, profile.store, ""); err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"attached", "detached", "hash"} {
				t.Run(operation, func(t *testing.T) {
					flags := ckalkan.SignCMS | profile.flags
					if operation != "attached" {
						flags |= ckalkan.DetachedData
					}
					var signed []byte
					var err error
					if operation == "hash" {
						digest, hashErr := client.HashData(profile.hash, 0, payload)
						if hashErr != nil {
							t.Fatal(hashErr)
						}
						signed, err = client.SignHash("", flags|ckalkan.OutDER|ckalkan.WithCert, digest)
					} else {
						signed, err = client.SignData(ckalkan.SignDataRequest{Flags: flags | ckalkan.OutDER | ckalkan.WithCert, Data: payload})
					}
					if err != nil {
						t.Fatal(err)
					}
					badSignature := tamperEmptyCMSSignature(t, signed)
					badPayload := bytes.Clone(payload)
					badPayload[len(badPayload)-1] ^= 1
					badContentCMS := bytes.Clone(signed)
					if operation == "attached" {
						if bytes.Count(signed, payload) != 1 {
							t.Fatal("expected one unambiguous attached payload")
						}
						copy(badContentCMS[bytes.Index(signed, payload):], badPayload)
					}
					if profile.name == "RSA" {
						verifyOpenSSLCMS(t, signed, payload, operation != "attached", true)
						verifyOpenSSLCMS(t, badSignature, payload, operation != "attached", false)
						if operation == "attached" {
							verifyOpenSSLCMS(t, badContentCMS, payload, false, false)
						} else {
							verifyOpenSSLCMS(t, signed, badPayload, true, false)
						}
					}
					for _, format := range []struct {
						name   string
						flag   ckalkan.Flag
						encode func([]byte) []byte
					}{
						{"DER", ckalkan.InDER, bytes.Clone},
						{"PEM", ckalkan.InPEM, func(b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: b}) }},
						{"Base64", ckalkan.InBase64, func(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(b)) }},
					} {
						for _, file := range []bool{false, true} {
							for _, secondaryBase64 := range []bool{false, true} {
								if operation == "attached" && secondaryBase64 {
									continue
								}
								t.Run(fmt.Sprintf("%s/file_%v/dataBase64_%v", format.name, file, secondaryBase64), func(t *testing.T) {
									request := ckalkan.VerifyDataRequest{Flags: flags | format.flag, CertID: 1}
									setSignature := func(der []byte) {
										request.Signature = format.encode(der)
										if file {
											path := filepath.Join(t.TempDir(), "signature")
											if err := os.WriteFile(path, request.Signature, 0o600); err != nil {
												t.Fatal(err)
											}
											request.Signature = []byte(path)
											request.Flags |= ckalkan.InFile
										}
									}
									setData := func(b []byte) {
										request.Data = b
										if secondaryBase64 {
											request.Data = []byte(base64.StdEncoding.EncodeToString(b))
											request.Flags |= ckalkan.In2Base64
										}
									}
									setSignature(signed)
									if operation != "attached" {
										setData(payload)
									}
									control, err := client.VerifyData(request)
									if err != nil || !strings.Contains(control.VerifyInfo, "Verify - OK") || len(control.Cert) == 0 {
										t.Fatalf("positive control = %+v, %v", control, err)
									}
									if operation == "attached" && !file && !bytes.Equal(control.Data, payload) {
										t.Fatalf("decoded payload = %x, want %x", control.Data, payload)
									}
									setSignature(badSignature)
									requireCMSCryptographicRejection(t, client, request, "signature")
									if operation == "attached" {
										setSignature(badContentCMS)
									} else {
										setSignature(signed)
										setData(badPayload)
									}
									requireCMSCryptographicRejection(t, client, request, "payload")
									setSignature(signed)
									if operation != "attached" {
										setData(payload)
									}
									if _, err := client.VerifyData(request); err != nil {
										t.Fatalf("valid CMS after rejections: %v", err)
									}
								})
							}
						}
					}
				})
			}
		})
	}
}

func TestVerifyOpenSSLSignatures(t *testing.T) {
	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)
	// No KalkanCrypt signing or loaded private key participates in this test.
	for _, detached := range []bool{false, true} {
		t.Run(fmt.Sprintf("detached_%v", detached), func(t *testing.T) {
			payload := []byte("independent OpenSSL signer\x00\xff\r\n")
			dataPath, signaturePath := filepath.Join(t.TempDir(), "payload"), filepath.Join(t.TempDir(), "signature.der")
			if err := os.WriteFile(dataPath, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"cms", "-sign", "-binary", "-md", "sha256", "-in", dataPath, "-signer", fixture.CertPath, "-inkey", fixture.KeyPath, "-outform", "DER", "-out", signaturePath}
			if !detached {
				args = append(args, "-nodetach")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if output, err := exec.CommandContext(ctx, requireOpenSSL(t), args...).CombinedOutput(); err != nil {
				t.Fatalf("OpenSSL signing: %v\n%s", err, output)
			}
			signed, err := os.ReadFile(signaturePath)
			if err != nil {
				t.Fatal(err)
			}
			request := ckalkan.VerifyDataRequest{Flags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime, Signature: signed, CertID: 1}
			if detached {
				request.Flags |= ckalkan.DetachedData
				request.Data = payload
			}
			control, err := client.VerifyData(request)
			if err != nil || !strings.Contains(control.VerifyInfo, "Verify - OK") || len(control.Cert) == 0 {
				t.Fatalf("independent positive control = %+v, %v", control, err)
			}
			request.Signature = tamperEmptyCMSSignature(t, signed)
			verifyOpenSSLCMS(t, request.Signature, payload, detached, false)
			requireCMSCryptographicRejection(t, client, request, "OpenSSL signature")
		})
	}
}

func TestVerifyOpenSSLMultiSignerCMS(t *testing.T) {
	client := newIntegrationClient(t)
	first, second := generatePKCS12Fixture(t), generatePKCS12Fixture(t)
	payload := []byte("both CMS signers must authenticate this payload\x00\xff")
	for _, detached := range []bool{false, true} {
		t.Run(fmt.Sprintf("detached_%v", detached), func(t *testing.T) {
			dir := t.TempDir()
			dataPath, signaturePath := filepath.Join(dir, "payload"), filepath.Join(dir, "signature.der")
			if err := os.WriteFile(dataPath, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{
				"cms", "-sign", "-binary", "-md", "sha256", "-in", dataPath, "-outform", "DER", "-out", signaturePath,
				"-signer", first.CertPath, "-inkey", first.KeyPath, "-signer", second.CertPath, "-inkey", second.KeyPath,
			}
			if !detached {
				args = append(args, "-nodetach")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if output, err := exec.CommandContext(ctx, requireOpenSSL(t), args...).CombinedOutput(); err != nil {
				t.Fatalf("OpenSSL multisigning: %v\n%s", err, output)
			}
			signed, err := os.ReadFile(signaturePath)
			if err != nil {
				t.Fatal(err)
			}
			verifyOpenSSLCMS(t, signed, payload, detached, true)
			var envelope struct {
				OID     asn1.ObjectIdentifier
				Content asn1.RawValue `asn1:"explicit,tag:0"`
			}
			if _, err := asn1.Unmarshal(signed, &envelope); err != nil {
				t.Fatal(err)
			}
			var content struct {
				Version      int
				Digests      asn1.RawValue
				Content      asn1.RawValue
				Certificates asn1.RawValue   `asn1:"optional,tag:0"`
				Revocations  asn1.RawValue   `asn1:"optional,tag:1"`
				Signers      []asn1.RawValue `asn1:"set"`
			}
			if _, err := asn1.Unmarshal(envelope.Content.Bytes, &content); err != nil || len(content.Signers) != 2 {
				t.Fatalf("need exactly two signers: %v", err)
			}
			for _, certID := range []int{0, 1, 2} {
				t.Run(fmt.Sprintf("certID_%d", certID), func(t *testing.T) {
					request := ckalkan.VerifyDataRequest{Flags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime, Signature: signed, CertID: certID}
					if detached {
						request.Flags |= ckalkan.DetachedData
						request.Data = payload
					}
					control, err := client.VerifyData(request)
					if err != nil || strings.Count(control.VerifyInfo, "\nVerify - OK") != 2 {
						t.Fatalf("two-signer control info = %q, %v", control.VerifyInfo, err)
					}
					for index, raw := range content.Signers {
						t.Run(fmt.Sprintf("changed_signer_%d", index+1), func(t *testing.T) {
							var signer struct {
								Version    int
								Identifier asn1.RawValue
								Digest     asn1.RawValue
								Attributes asn1.RawValue `asn1:"optional,tag:0"`
								Algorithm  asn1.RawValue
								Signature  []byte
							}
							if _, err := asn1.Unmarshal(raw.FullBytes, &signer); err != nil || len(signer.Signature) == 0 || bytes.Count(signed, signer.Signature) != 1 {
								t.Fatalf("need unambiguous signer signature: %v", err)
							}
							changed := bytes.Clone(signed)
							changed[bytes.Index(changed, signer.Signature)+len(signer.Signature)/2] ^= 1
							verifyOpenSSLCMS(t, changed, payload, detached, false)
							request.Signature = changed
							requireCMSCryptographicRejection(t, client, request, "one of two signer signatures")
						})
					}
				})
			}
		})
	}
}

func TestCMSVerificationChecksExpiredCertificate(t *testing.T) {
	client := newIntegrationClient(t)
	assets := loadFixtureAssets(t)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixturePassword, chooseStore(t, assets.P12), ""); err != nil {
		t.Fatal(err)
	}
	signed, err := client.SignData(ckalkan.SignDataRequest{Flags: ckalkan.SignCMS | ckalkan.OutDER | ckalkan.WithCert | ckalkan.NoCheckCertTime, Data: []byte("certificate time is checked separately from signature integrity")})
	if err != nil {
		t.Fatal(err)
	}
	request := ckalkan.VerifyDataRequest{Signature: signed, Flags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime}
	if result, err := client.VerifyData(request); err != nil || !strings.Contains(result.VerifyInfo, "Verify - OK") {
		t.Fatalf("historical signature integrity: %+v, %v", result, err)
	}
	request.Flags &^= ckalkan.NoCheckCertTime
	result, err := client.VerifyData(request)
	if code, ok := ckalkan.ErrorCodeOf(err); !ok || code != ckalkan.ErrorCertTimeInvalid || len(result.Data) != 0 {
		t.Fatalf("expired certificate = %+v, %v, want certificate-time rejection", result, err)
	}
}

// TestLiveTimestampVerification checks signatures with timestamps from the live
// TSA.
//
// Live tests are opt-in: service availability must not make the offline suite
// flaky. Failures of an enabled live test are never converted into skips.
func TestLiveTimestampVerification(t *testing.T) {
	if os.Getenv("KALKANCRYPT_LIVE_TESTS") != "1" {
		t.Skip("set KALKANCRYPT_LIVE_TESTS=1 to contact the actual NCA test TSA")
	}
	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)
	assets := loadFixtureAssets(t)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixture.Password, fixture.P12Path, ""); err != nil {
		t.Fatal(err)
	}
	for _, path := range assets.Certs {
		name := strings.ToLower(filepath.Base(path))
		role := ckalkan.CertIntermediate
		if strings.Contains(name, "root") {
			role = ckalkan.CertCA
		} else if !strings.Contains(name, "nca") {
			continue
		}
		if err := client.X509LoadCertificateFromFile(path, role); err != nil {
			t.Fatal(err)
		}
	}
	// The current test TSA uses the RSA test hierarchy, independently of the
	// signing key's algorithm. Download its public chain only in this live test.
	for _, ca := range []struct {
		name string
		role ckalkan.CertType
	}{{"root_rsa_test", ckalkan.CertCA}, {"nca_rsa_test", ckalkan.CertIntermediate}} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://test.pki.gov.kz/cert/"+ca.name+".cer", nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeErr := response.Body.Close()
		cancel()
		if response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil {
			t.Fatalf("download TSA CA: status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
		}
		path := filepath.Join(t.TempDir(), ca.name+".cer")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := client.X509LoadCertificateFromFile(path, ca.role); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.SetProxy(ckalkan.ProxyRequest{Flags: ckalkan.ProxyOff}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTSAURL("http://test.pki.gov.kz/tsp/"); err != nil {
		t.Fatal(err)
	}
	payload := []byte("live TSA authenticates this signature\x00\xff\r\n")
	for _, operation := range []string{"attached", "detached", "hash"} {
		t.Run(operation, func(t *testing.T) {
			flags := ckalkan.SignCMS | ckalkan.OutDER | ckalkan.WithCert | ckalkan.WithTimestamp | ckalkan.NoCheckCertTime
			if operation != "attached" {
				flags |= ckalkan.DetachedData
			}
			started := time.Now().Add(-2 * time.Minute)
			var signed []byte
			var err error
			if operation == "hash" {
				digest, hashErr := client.HashData(ckalkan.SHA256, 0, payload)
				if hashErr != nil {
					t.Fatal(hashErr)
				}
				signed, err = client.SignHash("", flags, digest)
			} else {
				signed, err = client.SignData(ckalkan.SignDataRequest{Flags: flags, Data: payload})
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("SignData/SignHash last native error: %s", client.GetLastError().Hex())
			if dir := os.Getenv("KALKANCRYPT_LIVE_RESULTS"); dir != "" {
				if err := os.WriteFile(filepath.Join(dir, "timestamped-"+operation+".der"), signed, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			request := ckalkan.VerifyDataRequest{Flags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime, Signature: signed}
			if operation != "attached" {
				request.Flags |= ckalkan.DetachedData
				request.Data = payload
			}
			verified, err := client.VerifyData(request)
			if err != nil || !strings.Contains(verified.VerifyInfo, "Verify - OK") || !strings.Contains(verified.VerifyInfo, "CAdES-T") {
				t.Fatalf("timestamped CMS verification = %+v, %v", verified, err)
			}
			if operation == "attached" && !bytes.Equal(verified.Data, payload) {
				t.Fatalf("timestamped attached payload = %x, want %x", verified.Data, payload)
			}
			timestamp, err := client.GetTimeFromSig(signed, ckalkan.InDER|ckalkan.NoCheckCertTime, 0)
			if err != nil || timestamp.Before(started) || timestamp.After(time.Now().Add(2*time.Minute)) {
				t.Fatalf("live timestamp = %v, %v; request started %v", timestamp, err, started)
			}
			t.Logf("verified live TSA timestamp: %s; CMS bytes: %d", timestamp.UTC().Format(time.RFC3339), len(signed))
			if operation == "attached" {
				verifyOpenSSLCMS(t, signed, payload, false, true)
			}
			token := cmsTimestampToken(t, signed)
			changedToken := tamperEmptyCMSSignature(t, token)
			request.Signature = bytes.Replace(signed, token, changedToken, 1)
			if bytes.Equal(request.Signature, signed) {
				t.Fatal("timestamp token signature mutation did not change the CMS")
			}
			result, err := client.VerifyData(request)
			if code, ok := ckalkan.ErrorCodeOf(err); !ok || (code != ckalkan.ErrorVerifyTSHash && uint64(code)>>24 != 4) || len(result.Data) != 0 {
				t.Fatalf("changed TSA signature = %+v, %v, want timestamp verification rejection", result, err)
			}
			// GetTimeFromSig extracts a value but does not authenticate it.
			// The VerifyData rejection above checks authentication.
			if extracted, err := client.GetTimeFromSig(request.Signature, ckalkan.InDER|ckalkan.NoCheckCertTime, 0); err != nil || !extracted.Equal(timestamp) {
				t.Fatalf("timestamp extraction = %v, %v, want unchanged embedded value %v", extracted, err, timestamp)
			}
		})
	}
}

func TestSignDataRejectsDuplicateSigner(t *testing.T) {
	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixture.Password, fixture.P12Path, ""); err != nil {
		t.Fatal(err)
	}
	flags := ckalkan.SignCMS | ckalkan.OutDER | ckalkan.WithCert | ckalkan.NoCheckCertTime
	payload := []byte("duplicate signer must not produce a successful result")
	signed, err := client.SignData(ckalkan.SignDataRequest{Flags: flags, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SignData(ckalkan.SignDataRequest{Flags: flags | ckalkan.InDER, Data: payload, Signature: signed})
	if code, ok := ckalkan.ErrorCodeOf(err); !ok || code != ckalkan.ErrorSign || result != nil {
		t.Fatalf("duplicate signer = %d bytes, %v, want ErrorSign without output", len(result), err)
	}
	control, err := client.VerifyData(ckalkan.VerifyDataRequest{Flags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime, Signature: signed})
	if err != nil || !bytes.Equal(control.Data, payload) {
		t.Fatalf("original CMS after rejected co-signing = %+v, %v", control, err)
	}
}

func TestSigningRejectsFailedTimestamp(t *testing.T) {
	client := newIntegrationClient(t)
	fixture := generatePKCS12Fixture(t)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixture.Password, fixture.P12Path, ""); err != nil {
		t.Fatal(err)
	}
	requests := make(chan struct{}, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			requests <- struct{}{}
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	if err := client.SetTSAURL(server.URL); err != nil {
		t.Fatal(err)
	}
	payload := []byte("timestamp authority failure must fail signing")
	digest, err := client.HashData(ckalkan.SHA256, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"SignData", "SignHash"} {
		t.Run(operation, func(t *testing.T) {
			flags := ckalkan.SignCMS | ckalkan.OutDER | ckalkan.WithCert | ckalkan.NoCheckCertTime
			if operation == "SignHash" {
				flags |= ckalkan.DetachedData
			}
			sign := func(flags ckalkan.Flag) ([]byte, error) {
				if operation == "SignHash" {
					return client.SignHash("", flags, digest)
				}
				return client.SignData(ckalkan.SignDataRequest{Flags: flags, Data: payload})
			}
			signed, err := sign(flags | ckalkan.WithTimestamp)
			t.Logf("failed TSA: outputBytes=%d error=%v lastError=%s", len(signed), err, client.GetLastError().Hex())
			requireKalkanError(t, operation+"(failed TSA)", err)
			if signed != nil {
				t.Fatal("failed timestamp request returned signature output")
			}
			select {
			case <-requests:
			default:
				t.Fatal("native signer did not contact the HTTP TSA")
			}
			control, err := sign(flags)
			if err != nil {
				t.Fatalf("signing without TSA after failure: %v", err)
			}
			request := ckalkan.VerifyDataRequest{Signature: control, Flags: ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime}
			if operation == "SignHash" {
				request.Flags |= ckalkan.DetachedData
				request.Data = payload
			}
			verified, err := client.VerifyData(request)
			if err != nil || !strings.Contains(verified.VerifyInfo, "Verify - OK") {
				t.Fatalf("positive control without TSA = %+v, %v", verified, err)
			}
			if operation == "SignData" && !bytes.Equal(verified.Data, payload) {
				t.Fatalf("positive control returned payload %x, want %x", verified.Data, payload)
			}
		})
	}
}
