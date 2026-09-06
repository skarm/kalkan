package isolated_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/isolated"
)

// This complete application hashes a file in an isolated SDK process.
// Copy the function into package main as main, keeping the imports.
func ExampleOpen() {
	// In an application, this branch belongs at the start of main, before
	// starting services. The same executable handles parent and worker modes.
	if len(os.Args) == 2 && os.Args[1] == "--kalkan-worker" {
		if err := isolated.RunWorker(context.Background()); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Return through this function so Close runs before log.Fatal exits.
	if err := func() (err error) {
		library := os.Getenv("KALKANCRYPT_LIBRARY")
		if library == "" {
			return errors.New("set KALKANCRYPT_LIBRARY to the SDK shared library path")
		}

		input := "/data/document.bin"
		libraryPath, err := filepath.Abs(library)
		if err != nil {
			return err
		}

		executable, err := os.Executable()
		if err != nil {
			return err
		}

		// The application owns cancellation, including while closing the SDK.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		client, err := isolated.Open(ctx, isolated.Config{
			WorkerPath:  executable,
			WorkerArgs:  []string{"--kalkan-worker"},
			LibraryPath: libraryPath,
		})
		if err != nil {
			return fmt.Errorf("open isolated SDK: %w", err)
		}
		defer func() { err = errors.Join(err, client.CloseContext(ctx)) }()

		digest, err := client.Hash(ctx, kalkan.HashRequest{
			Algorithm: kalkan.SHA256,
			Data:      kalkan.File(input),
		})
		if err != nil {
			return fmt.Errorf("hash: %w", err)
		}

		_, err = fmt.Printf("%x\n", digest.Data)
		return err
	}(); err != nil {
		log.Fatal(err)
	}
}

// This complete application loads a PKCS#12 key, signs a file, verifies the
// detached CMS against the original bytes, and saves the result as DER.
// Copy the function into package main as main, keeping the imports. Use a valid
// signing certificate and its CA chain; certificate-time checks remain enabled.
func ExampleClient_SignCMS() {
	// In an application, this branch belongs at the start of main, before
	// starting services. The same executable handles parent and worker modes.
	if len(os.Args) == 2 && os.Args[1] == "--kalkan-worker" {
		if err := isolated.RunWorker(context.Background()); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Return through this function so Close runs before log.Fatal exits.
	if err := func() (err error) {
		library := os.Getenv("KALKANCRYPT_LIBRARY")
		if library == "" {
			return errors.New("set KALKANCRYPT_LIBRARY to the SDK shared library path")
		}

		password, ok := os.LookupEnv("KALKAN_KEY_PASSWORD")
		if !ok {
			return errors.New("set KALKAN_KEY_PASSWORD to the PKCS#12 password (may be empty)")
		}

		keyStore := "/etc/kalkan/signing.p12"
		root := "/etc/kalkan/root.cer"
		intermediate := "/etc/kalkan/intermediate.cer"
		input := "/data/document.bin"
		output := "/data/document.cms"

		libraryPath, err := filepath.Abs(library)
		if err != nil {
			return err
		}

		payload, err := os.ReadFile(input)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}

		executable, err := os.Executable()
		if err != nil {
			return err
		}

		// The application owns cancellation, including while closing the SDK.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		client, err := isolated.Open(ctx, isolated.Config{
			WorkerPath:  executable,
			WorkerArgs:  []string{"--kalkan-worker"},
			LibraryPath: libraryPath,
			TrustedCertificates: []kalkan.TrustedCertificate{
				{Path: root, Type: kalkan.CertificateCA},
				{Path: intermediate, Type: kalkan.CertificateIntermediate},
			},
		})
		if err != nil {
			return fmt.Errorf("open isolated SDK: %w", err)
		}
		defer func() { err = errors.Join(err, client.CloseContext(ctx)) }()

		// This client belongs to this signing flow; another key cannot interleave.
		if err := client.LoadKeyStore(ctx, kalkan.KeyStore{
			Type: kalkan.PKCS12, Path: keyStore, Password: password,
		}); err != nil {
			return fmt.Errorf("load key store: %w", err)
		}

		signed, err := client.SignCMS(ctx, kalkan.SignCMSRequest{
			Data: kalkan.Bytes(payload), Detached: true, IncludeCertificate: true,
		})
		if err != nil {
			return fmt.Errorf("sign CMS: %w", err)
		}

		if _, err := client.VerifyCMS(ctx, kalkan.VerifyCMSRequest{
			Signature: kalkan.DER(signed.Data), Data: kalkan.Bytes(payload), Detached: true,
		}); err != nil {
			return fmt.Errorf("verify CMS: %w", err)
		}

		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create signature: %w", err)
		}

		_, writeErr := file.Write(signed.Data)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return fmt.Errorf("write signature: %w", err)
		}

		_, err = fmt.Printf("Signature verified and saved to %s\n", output)
		return err
	}(); err != nil {
		log.Fatal(err)
	}
}
