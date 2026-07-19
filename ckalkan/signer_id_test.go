package ckalkan

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestVerifyDataValidatesCertID(t *testing.T) {
	t.Run("negative rejected", func(t *testing.T) {
		ctx := &fakeNativeContext{
			verifyDataFunc: func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
				t.Error("VerifyData reached native for negative CertID")
				return kalkancrypt.VerifyResult{}, nil
			},
		}
		cli := &Client{ctx: ctx, config: defaultConfig()}

		_, err := cli.VerifyData(VerifyDataRequest{Flags: SignCMS, CertID: -1})
		if err == nil || !strings.Contains(err.Error(), "CertID") || !strings.Contains(err.Error(), "non-negative") {
			t.Fatalf("VerifyData error = %v, want CertID non-negative validation error", err)
		}
	})

	t.Run("max native signer id allowed", func(t *testing.T) {
		ctx := &fakeNativeContext{
			verifyDataFunc: func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
				if call.CertID != maxNativeCInt {
					t.Fatalf("CertID = %d, want max signer id %d", call.CertID, maxNativeCInt)
				}

				return kalkancrypt.VerifyResult{Code: uint64(ErrorOK)}, nil
			},
		}
		cli := &Client{ctx: ctx, config: defaultConfig()}

		if _, err := cli.VerifyData(VerifyDataRequest{Flags: SignCMS, CertID: maxNativeCInt}); err != nil {
			t.Fatalf("VerifyData returned error: %v", err)
		}
	})

	t.Run("overflow rejected", func(t *testing.T) {
		ctx := &fakeNativeContext{
			verifyDataFunc: func(call kalkancrypt.VerifyDataCall) (kalkancrypt.VerifyResult, error) {
				t.Error("VerifyData reached native for overflowing CertID")
				return kalkancrypt.VerifyResult{}, nil
			},
		}
		cli := &Client{ctx: ctx, config: defaultConfig()}

		_, err := cli.VerifyData(VerifyDataRequest{Flags: SignCMS, CertID: signIDOverflowValue(t)})
		if err == nil || !strings.Contains(err.Error(), "CertID") || !strings.Contains(err.Error(), strconv.Itoa(maxNativeCInt)) {
			t.Fatalf("VerifyData error = %v, want CertID overflow validation error", err)
		}
	})
}

func TestCertificateExtractionValidatesSignID(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client, int) ([]byte, error)
		ctx  func(*testing.T, int) *fakeNativeContext
	}{
		{
			name: "GetCertFromCMS",
			call: func(cli *Client, signID int) ([]byte, error) {
				return cli.GetCertFromCMS([]byte("cms"), signID, InBase64)
			},
			ctx: func(t *testing.T, wantSignID int) *fakeNativeContext {
				return &fakeNativeContext{
					getCertFromCMSFunc: func(call kalkancrypt.GetCertFromCMSCall) (kalkancrypt.BufferResult, error) {
						if call.SignID != wantSignID {
							t.Fatalf("signID = %d, want %d", call.SignID, wantSignID)
						}

						return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
					},
				}
			},
		},
		{
			name: "GetCertFromXML",
			call: func(cli *Client, signID int) ([]byte, error) {
				return cli.GetCertFromXML([]byte("<root/>"), signID)
			},
			ctx: func(t *testing.T, wantSignID int) *fakeNativeContext {
				return &fakeNativeContext{
					getCertFromXMLFunc: func(xml []byte, signID, capacity int) (kalkancrypt.BufferResult, error) {
						if signID != wantSignID {
							t.Fatalf("signID = %d, want %d", signID, wantSignID)
						}

						return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
					},
				}
			},
		},
		{
			name: "GetCertFromZipFile",
			call: func(cli *Client, signID int) ([]byte, error) {
				return cli.GetCertFromZipFile("/tmp/signed.zip", InFile, signID)
			},
			ctx: func(t *testing.T, wantSignID int) *fakeNativeContext {
				return &fakeNativeContext{
					getCertFromZipFileFunc: func(call kalkancrypt.GetCertFromZipFileCall) (kalkancrypt.BufferResult, error) {
						if call.SignID != wantSignID {
							t.Fatalf("signID = %d, want %d", call.SignID, wantSignID)
						}

						return kalkancrypt.BufferResult{Code: uint64(ErrorOK)}, nil
					},
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name+"/negative rejected", func(t *testing.T) {
			ctx := test.ctx(t, 0)
			ctx.getCertFromCMSFunc = failGetCertFromCMS(t)
			ctx.getCertFromXMLFunc = failGetCertFromXML(t)
			ctx.getCertFromZipFileFunc = failGetCertFromZipFile(t)
			cli := &Client{ctx: ctx, config: defaultConfig()}

			_, err := test.call(cli, -1)
			if err == nil || !strings.Contains(err.Error(), "signID") || !strings.Contains(err.Error(), "non-negative") {
				t.Fatalf("%s error = %v, want signID non-negative validation error", test.name, err)
			}
		})

		t.Run(test.name+"/max native signer id allowed", func(t *testing.T) {
			cli := &Client{ctx: test.ctx(t, maxNativeCInt), config: defaultConfig()}

			if _, err := test.call(cli, maxNativeCInt); err != nil {
				t.Fatalf("%s returned error: %v", test.name, err)
			}
		})

		t.Run(test.name+"/overflow rejected", func(t *testing.T) {
			ctx := test.ctx(t, 0)
			ctx.getCertFromCMSFunc = failGetCertFromCMS(t)
			ctx.getCertFromXMLFunc = failGetCertFromXML(t)
			ctx.getCertFromZipFileFunc = failGetCertFromZipFile(t)
			cli := &Client{ctx: ctx, config: defaultConfig()}

			_, err := test.call(cli, signIDOverflowValue(t))
			if err == nil || !strings.Contains(err.Error(), "signID") || !strings.Contains(err.Error(), strconv.Itoa(maxNativeCInt)) {
				t.Fatalf("%s error = %v, want signID overflow validation error", test.name, err)
			}
		})
	}
}

func TestGetTimeFromSigValidatesSigID(t *testing.T) {
	t.Run("negative rejected", func(t *testing.T) {
		ctx := &fakeNativeContext{
			getTimeFromSigFunc: func(data []byte, flags, sigID int) (uint64, int64) {
				t.Error("GetTimeFromSig reached native for negative sigID")
				return uint64(ErrorOK), 0
			},
		}
		cli := &Client{ctx: ctx, config: defaultConfig()}

		_, err := cli.GetTimeFromSig([]byte("cms"), InBase64, -1)
		if err == nil || !strings.Contains(err.Error(), "sigID") || !strings.Contains(err.Error(), "non-negative") {
			t.Fatalf("GetTimeFromSig error = %v, want sigID non-negative validation error", err)
		}
	})

	t.Run("max native sig id allowed", func(t *testing.T) {
		wantTime := time.Unix(1_700_000_000, 0)
		ctx := &fakeNativeContext{
			getTimeFromSigFunc: func(data []byte, flags, sigID int) (uint64, int64) {
				if sigID != maxNativeCInt {
					t.Fatalf("sigID = %d, want max native C int %d", sigID, maxNativeCInt)
				}

				return uint64(ErrorOK), wantTime.Unix()
			},
		}
		cli := &Client{ctx: ctx, config: defaultConfig()}

		got, err := cli.GetTimeFromSig([]byte("cms"), InBase64, maxNativeCInt)
		if err != nil {
			t.Fatalf("GetTimeFromSig returned error: %v", err)
		}
		if !got.Equal(wantTime) {
			t.Fatalf("GetTimeFromSig time = %v, want %v", got, wantTime)
		}
	})

	t.Run("overflow rejected", func(t *testing.T) {
		ctx := &fakeNativeContext{
			getTimeFromSigFunc: func(data []byte, flags, sigID int) (uint64, int64) {
				t.Error("GetTimeFromSig reached native for overflowing sigID")
				return uint64(ErrorOK), 0
			},
		}
		cli := &Client{ctx: ctx, config: defaultConfig()}

		_, err := cli.GetTimeFromSig([]byte("cms"), InBase64, signIDOverflowValue(t))
		if err == nil || !strings.Contains(err.Error(), "sigID") || !strings.Contains(err.Error(), strconv.Itoa(maxNativeCInt)) {
			t.Fatalf("GetTimeFromSig error = %v, want sigID overflow validation error", err)
		}
	})
}

func signIDOverflowValue(t *testing.T) int {
	t.Helper()
	if strconv.IntSize <= 32 {
		t.Skip("signID overflow value is not representable as int on this platform")
	}

	return int(int64(maxNativeCInt) + 1)
}

func failGetCertFromCMS(t *testing.T) func(kalkancrypt.GetCertFromCMSCall) (kalkancrypt.BufferResult, error) {
	t.Helper()

	return func(call kalkancrypt.GetCertFromCMSCall) (kalkancrypt.BufferResult, error) {
		t.Error("GetCertFromCMS reached native for invalid signID")
		return kalkancrypt.BufferResult{}, nil
	}
}

func failGetCertFromXML(t *testing.T) func([]byte, int, int) (kalkancrypt.BufferResult, error) {
	t.Helper()

	return func(xml []byte, signID, capacity int) (kalkancrypt.BufferResult, error) {
		t.Error("GetCertFromXML reached native for invalid signID")
		return kalkancrypt.BufferResult{}, nil
	}
}

func failGetCertFromZipFile(t *testing.T) func(kalkancrypt.GetCertFromZipFileCall) (kalkancrypt.BufferResult, error) {
	t.Helper()

	return func(call kalkancrypt.GetCertFromZipFileCall) (kalkancrypt.BufferResult, error) {
		t.Error("GetCertFromZipFile reached native for invalid signID")
		return kalkancrypt.BufferResult{}, nil
	}
}
