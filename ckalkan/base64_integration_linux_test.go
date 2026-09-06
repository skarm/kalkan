//go:build linux && amd64 && cgo

package ckalkan_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestBase64CMSInputsAtGuardPage(t *testing.T) {
	if os.Getenv("KALKANCRYPT_LIBRARY") == "" {
		t.Skip("set KALKANCRYPT_LIBRARY to run native memory-boundary tests")
	}
	const childOperation = "KALKANCRYPT_BASE64_BOUNDARY_OPERATION"
	const completionMarker = "completed native Base64 boundary: "
	if operation := os.Getenv(childOperation); operation != "" {
		checkBase64CMSInputAtGuardPage(t, operation)
		t.Log(completionMarker + operation)
		return
	}

	// Isolate a native out-of-bounds read so it fails only this subtest instead
	// of terminating the entire test binary. No NUL is accessible past the input.
	for _, operation := range []string{"SignData", "VerifyData", "GetCertFromCMS", "GetTimeFromSig"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBase64CMSInputsAtGuardPage$", "-test.v")
			command.Env = append(os.Environ(), childOperation+"="+operation)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("native %s guard-page check failed: %v\n%s", operation, err, output)
			}
			if !bytes.Contains(output, []byte(completionMarker+operation)) {
				t.Fatalf("native %s guard-page check did not complete (possibly skipped):\n%s", operation, output)
			}
		})
	}
}

func checkBase64CMSInputAtGuardPage(t *testing.T, operation string) {
	t.Helper()
	assets := loadFixtureAssets(t)
	client := newIntegrationClient(t, ckalkan.WithBufferSize(8<<10))
	loadCertificates(t, client, assets)
	if err := client.LoadKeyStore(ckalkan.StorePKCS12, fixturePassword, chooseStore(t, assets.P12), ""); err != nil {
		t.Fatal(err)
	}
	payload := []byte("native Base64 boundary\x00payload")
	flags := ckalkan.SignCMS | ckalkan.OutDER | ckalkan.WithCert | ckalkan.NoCheckCertTime

	if operation == "SignData" {
		encoded := []byte(base64.StdEncoding.EncodeToString(payload))
		signed, err := client.SignData(ckalkan.SignDataRequest{
			Flags: flags | ckalkan.InBase64,
			Data:  bytesAtGuardPage(t, encoded),
		})
		if err != nil {
			t.Fatal(err)
		}
		verified, err := client.VerifyData(ckalkan.VerifyDataRequest{
			Flags:     ckalkan.SignCMS | ckalkan.InDER | ckalkan.NoCheckCertTime,
			Signature: signed,
		})
		if err != nil || !bytes.Equal(verified.Data, payload) {
			t.Fatalf("VerifyData after guarded signing = %q, %v, want original binary payload", verified.Data, err)
		}
		return
	}

	signed, err := client.SignData(ckalkan.SignDataRequest{Flags: flags, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(signed))
	input := bytesAtGuardPage(t, encoded)
	switch operation {
	case "VerifyData":
		verified, err := client.VerifyData(ckalkan.VerifyDataRequest{
			Flags:     ckalkan.SignCMS | ckalkan.InBase64 | ckalkan.NoCheckCertTime,
			Signature: input,
		})
		if err != nil || !bytes.Equal(verified.Data, payload) {
			t.Fatalf("guarded VerifyData = %q, %v, want original binary payload", verified.Data, err)
		}
	case "GetCertFromCMS":
		// Linux SDK 2.0.13 numbers signer certificates from one.
		certificate, err := client.GetCertFromCMS(input, 1, ckalkan.InBase64|ckalkan.OutDER)
		if err != nil || len(certificate) == 0 {
			t.Fatalf("guarded GetCertFromCMS returned %d bytes, %v, want signer certificate", len(certificate), err)
		}
		if _, err := x509.ParseCertificate(certificate); err != nil {
			t.Fatalf("guarded GetCertFromCMS returned invalid certificate: %v", err)
		}
	case "GetTimeFromSig":
		_, err := client.GetTimeFromSig(input, ckalkan.InBase64, 0)
		code, ok := ckalkan.ErrorCodeOf(err)
		if !ok || code != ckalkan.ErrorNoTSAToken {
			t.Fatalf("guarded GetTimeFromSig = %v, want ErrorNoTSAToken for untimestamped CMS", err)
		}
	default:
		t.Fatalf("unknown guard-page operation %q", operation)
	}
}

func bytesAtGuardPage(t *testing.T, input []byte) []byte {
	t.Helper()
	pageSize := os.Getpagesize()
	accessible := (len(input) + pageSize - 1) / pageSize * pageSize
	mapping, err := syscall.Mmap(-1, 0, accessible+pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Munmap(mapping); err != nil {
			t.Error(err)
		}
	})
	if err := syscall.Mprotect(mapping[accessible:], syscall.PROT_NONE); err != nil {
		t.Fatal(err)
	}
	buffer := mapping[accessible-len(input) : accessible : accessible]
	copy(buffer, input)
	return buffer
}
