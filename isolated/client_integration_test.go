package isolated_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/isolated"
)

const sdkFixturePassword = "Qwerty12" // Public historical fixtures; see testdata/README.md.

func TestSDKIsolatedClientsHaveIndependentSessions(t *testing.T) {
	config, stores := sdkFixtureConfig(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	closeObservations := [2]chan kalkan.OperationObservation{
		make(chan kalkan.OperationObservation, 4),
		make(chan kalkan.OperationObservation, 4),
	}
	type openedClient struct {
		index  int
		client *isolated.Client
		err    error
	}
	opened := make(chan openedClient, 2)
	for index := range 2 {
		go func() {
			workerConfig := config
			workerConfig.Observer = func(_ context.Context, observation kalkan.OperationObservation) {
				if observation.Operation == "Close" {
					closeObservations[index] <- observation
				}
			}
			client, err := isolated.Open(ctx, workerConfig)
			if err == nil {
				err = client.LoadKeyStore(ctx, kalkan.KeyStore{Path: stores[index], Password: sdkFixturePassword})
			}
			opened <- openedClient{index, client, err}
		}()
	}
	var clients [2]*isolated.Client
	var failures [2]error
	for range 2 {
		result := <-opened
		clients[result.index], failures[result.index] = result.client, result.err
		if result.client != nil {
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := result.client.CloseContext(ctx); err != nil {
					t.Errorf("Close SDK worker %d: %v", result.index, err)
				}
			})
		}
	}
	for index, err := range failures {
		if err != nil {
			t.Fatalf("Open/LoadKeyStore worker %d: %v", index, err)
		}
	}

	// Export only after BOTH workers have loaded their different keys. A shared
	// in-process SDK session cannot satisfy these independent identities.
	var certificates [2]*x509.Certificate
	for index, client := range clients {
		certificate, err := client.X509ExportCertificateFromStore(ctx)
		if err != nil || certificate == nil {
			t.Fatalf("export worker %d certificate = %#v, %v", index, certificate, err)
		}
		certificates[index] = certificate
	}
	if bytes.Equal(certificates[0].Raw, certificates[1].Raw) {
		t.Fatal("two workers loaded the same certificate despite different PKCS#12 fixtures")
	}

	t.Run("parallel operations", func(t *testing.T) {
		for index, client := range clients {
			t.Run(filepath.Base(stores[index]), func(t *testing.T) {
				t.Parallel()
				assertSDKWorkerOperations(t, ctx, client, certificates[index])
			})
		}
	})

	if err := clients[0].CloseContext(ctx); err != nil {
		t.Fatalf("close first SDK worker: %v", err)
	}
	if _, err := clients[0].Hash(ctx, kalkan.HashRequest{Data: kalkan.Bytes([]byte("closed"))}); !errors.Is(err, kalkan.ErrClosed) {
		t.Fatalf("first worker Hash after Close = %v, want ErrClosed", err)
	}
	remaining, err := clients[1].X509ExportCertificateFromStore(ctx)
	if err != nil || remaining == nil || !bytes.Equal(remaining.Raw, certificates[1].Raw) {
		t.Fatalf("closing first worker changed second worker's certificate: %v", err)
	}
	assertSDKDetachedCMS(t, ctx, clients[1], []byte("second worker remains usable"), certificates[1])
	if err := clients[1].CloseContext(ctx); err != nil {
		t.Fatalf("close second SDK worker: %v", err)
	}
	assertSDKCloseObservations(t, clients, closeObservations)
}

func assertSDKCloseObservations(t *testing.T, clients [2]*isolated.Client, observations [2]chan kalkan.OperationObservation) {
	t.Helper()
	for index, client := range clients {
		// Close publishes its saved result before invoking the observer. A
		// repeated Close must neither lose nor repeat the worker's observation.
		if err := client.Close(); err != nil {
			t.Fatalf("repeat Close SDK worker %d: %v", index, err)
		}
		select {
		case observation := <-observations[index]:
			if observation.ErrorClass != "none" || observation.NativeCode != 0 || observation.Expected {
				t.Fatalf("Close observation worker %d = %+v, want successful native Close", index, observation)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Close observation missing for SDK worker %d", index)
		}
	}
	// Allow asynchronous callbacks from either completed Close to arrive;
	// neither the first nor repeated Close may produce another observation.
	select {
	case observation := <-observations[0]:
		t.Fatalf("duplicate Close observation for SDK worker 0: %+v", observation)
	case observation := <-observations[1]:
		t.Fatalf("duplicate Close observation for SDK worker 1: %+v", observation)
	case <-time.After(100 * time.Millisecond):
	}
}

func assertSDKWorkerOperations(t *testing.T, ctx context.Context, client *isolated.Client, certificate *x509.Certificate) {
	t.Helper()
	payload := []byte{'d', 'a', 't', 'a', 0, 0xff, 1}
	wantHash := sha256.Sum256(payload)
	digest, err := client.Hash(ctx, kalkan.HashRequest{Algorithm: kalkan.SHA256, Data: kalkan.Bytes(payload)})
	if err != nil || digest == nil || !bytes.Equal(digest.Data, wantHash[:]) || digest.Algorithm != kalkan.SHA256 {
		t.Fatalf("Hash = %#v, %v, want exact SHA-256 of binary input", digest, err)
	}
	assertSDKDetachedCMS(t, ctx, client, payload, certificate)
	assertSDKSignHash(t, ctx, client, payload)

	info, err := client.X509CertificateGetInfoFields(ctx, certificate, kalkan.CertificateInfoSubject|kalkan.CertificateInfoSerialNumber)
	if err != nil || info == nil || info.Subject == "" || info.SerialNumber == "" {
		t.Fatalf("X509CertificateGetInfoFields = %#v, %v", info, err)
	}
	validation, err := client.ValidateCertificate(ctx, kalkan.ValidateCertificateRequest{
		Certificate: kalkan.DER(certificate.Raw), Mode: kalkan.CertificateValidationNone,
		CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
	})
	if err != nil || validation == nil || !strings.Contains(validation.Info, "- OK") || validation.OCSPResponse != nil {
		t.Fatalf("ValidateCertificate = %#v, %v, want trusted chain and no unrequested OCSP output", validation, err)
	}

	signed, err := client.SignXML(ctx, kalkan.SignXMLRequest{
		XML:                  kalkan.Bytes([]byte(`<document><payload>Изолированная подпись</payload></document>`)),
		CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
	})
	if err != nil || signed == nil {
		t.Fatalf("SignXML = %#v, %v", signed, err)
	}
	verification, err := client.VerifyXML(ctx, kalkan.VerifyXMLRequest{XML: kalkan.Bytes(signed.XML), CertificateTimeCheck: kalkan.SkipCertificateTimeCheck})
	if err != nil || verification == nil || !strings.Contains(verification.Info, "OK") {
		t.Fatalf("VerifyXML = %#v, %v", verification, err)
	}
	extracted, err := client.GetCertFromXML(ctx, kalkan.Bytes(signed.XML))
	if err != nil || len(extracted) != 1 || !bytes.Equal(extracted[0].Raw, certificate.Raw) {
		t.Fatalf("GetCertFromXML returned %d certificates, %v; want this worker's signer", len(extracted), err)
	}
	algorithm, err := client.GetSigAlgFromXML(ctx, kalkan.Bytes(signed.XML))
	if err != nil || algorithm == "" {
		t.Fatalf("GetSigAlgFromXML = %q, %v", algorithm, err)
	}
}

func assertSDKDetachedCMS(t *testing.T, ctx context.Context, client *isolated.Client, payload []byte, certificate *x509.Certificate) {
	t.Helper()
	signed, err := client.SignCMS(ctx, kalkan.SignCMSRequest{
		Data: kalkan.Bytes(payload), Detached: true, IncludeCertificate: true,
		CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
	})
	if err != nil || signed == nil {
		t.Fatalf("SignCMS = %#v, %v", signed, err)
	}
	verification, err := client.VerifyCMS(ctx, kalkan.VerifyCMSRequest{
		Signature: kalkan.DER(signed.Data), Data: kalkan.Bytes(payload), Detached: true,
		CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
	})
	if err != nil || verification == nil || !strings.Contains(verification.Info, "Verify - OK") {
		t.Fatalf("VerifyCMS = %#v, %v", verification, err)
	}
	extracted, err := client.GetCertFromCMS(ctx, kalkan.DER(signed.Data))
	if err != nil {
		t.Fatalf("GetCertFromCMS: %v", err)
	}
	for _, found := range extracted {
		if found != nil && bytes.Equal(found.Raw, certificate.Raw) {
			return
		}
	}
	t.Fatalf("GetCertFromCMS returned %d certificates without this worker's signer", len(extracted))
}

func assertSDKSignHash(t *testing.T, ctx context.Context, client *isolated.Client, payload []byte) {
	t.Helper()
	digest, err := client.Hash(ctx, kalkan.HashRequest{Algorithm: kalkan.GOST2015_512, Data: kalkan.Bytes(payload)})
	if err != nil || digest == nil || len(digest.Data) != 64 {
		t.Fatalf("Hash GOST512 = %#v, %v", digest, err)
	}
	signed, err := client.SignHash(ctx, kalkan.SignHashRequest{
		Digest: digest.Data, DigestAlgorithm: kalkan.GOST2015_512, IncludeCertificate: true,
		CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
	})
	if err != nil || signed == nil {
		t.Fatalf("SignHash = %#v, %v", signed, err)
	}
	request := kalkan.VerifyCMSRequest{
		Signature: kalkan.DER(signed.Data), Data: kalkan.Bytes(payload), Detached: true,
		CertificateTimeCheck: kalkan.SkipCertificateTimeCheck,
	}
	verified, err := client.VerifyCMS(ctx, request)
	if err != nil || verified == nil || !strings.Contains(verified.Info, "Verify - OK") {
		t.Fatalf("VerifyCMS SignHash original = %#v, %v", verified, err)
	}
	tampered := bytes.Clone(payload)
	tampered[0] ^= 1
	request.Data = kalkan.Bytes(tampered)
	_, err = client.VerifyCMS(ctx, request)
	// Linux SDK 2.0.13 exposes this OpenSSL digest-verification error directly.
	const digestVerificationFailure = ckalkan.ErrorCode(0x2E09A09E)
	if code, ok := ckalkan.ErrorCodeOf(err); !ok || code != digestVerificationFailure {
		t.Fatalf("VerifyCMS SignHash altered payload = %v, want native code %s", err, digestVerificationFailure.Hex())
	}
}

func sdkFixtureConfig(t *testing.T) (isolated.Config, []string) {
	t.Helper()
	library := os.Getenv("KALKANCRYPT_LIBRARY")
	if library == "" {
		t.Skip("set KALKANCRYPT_LIBRARY to run actual SDK worker integration tests")
	}
	assetRoot := os.Getenv("KALKANCRYPT_SDK_ASSETS")
	if assetRoot == "" {
		assetRoot = filepath.Join("..", "testdata")
	}
	assetRoot, err := filepath.Abs(assetRoot)
	if err != nil {
		t.Fatal(err)
	}
	stores, err := filepath.Glob(filepath.Join(assetRoot, "p12", "GOST512_*.p12"))
	if err != nil || len(stores) < 2 {
		t.Fatalf("need two historical GOST512 fixtures under %s: stores=%d error=%v", assetRoot, len(stores), err)
	}
	library, err = filepath.Abs(library)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return isolated.Config{
		WorkerPath: executable, LibraryPath: library,
		WorkerArgs: []string{"-test.run=^TestSDKWorkerHelper$", "--", "kalkan-sdk-worker"},
		TrustedCertificates: []kalkan.TrustedCertificate{
			{Path: filepath.Join(assetRoot, "certs", "root_test_gost_2022.cer"), Type: kalkan.CertificateCA},
			{Path: filepath.Join(assetRoot, "certs", "nca_gost2022_test.cer"), Type: kalkan.CertificateIntermediate},
		},
	}, stores[:2]
}
