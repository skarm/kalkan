package kalkan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestKeyStoreRestoresConfiguredAndRuntimeTrustWithoutDuplicates(t *testing.T) {
	loads := make(map[string]int)
	native := &fakeNative{
		loadKeyStoreFunc: func(ckalkan.Store, string, string, string) error {
			clear(loads) // A successful SDK key-store load resets trust.
			return nil
		},
		loadCertFileFunc: func(path string, role ckalkan.CertType) error {
			loads[fmt.Sprintf("file:%s:%d", path, role)]++
			return nil
		},
		loadCertBufferFunc: func(data []byte, format ckalkan.CertFormat) error {
			loads[fmt.Sprintf("buffer:%s:%d", data, format)]++
			return nil
		},
	}
	configured := TrustedCertificate{Path: "/tmp/ca.pem", Type: CertificateCA}
	client, err := openWithLibraryFactory(context.Background(), []Option{
		WithLibraryPath(testLibraryPath()), WithTrustedCertificate(configured),
	}, func(config) (closer, error) { return native, nil })
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer client.Close()

	data := []byte("runtime certificate")
	runtimeCert := TrustedCertificate{Data: data, Type: CertificateIntermediate, Format: CertificatePEM}
	for _, cert := range []TrustedCertificate{
		configured, runtimeCert, runtimeCert,
		{Path: configured.Path, Type: CertificateIntermediate},
		{Data: bytes.Clone(data), Type: CertificateIntermediate, Format: CertificateDER},
		{Data: bytes.Clone(data), Type: CertificateUser, Format: CertificatePEM},
	} {
		if err := client.LoadTrustedCertificate(context.Background(), cert); err != nil {
			t.Fatalf("LoadTrustedCertificate: %v", err)
		}
	}
	clear(data)
	// Buffer loads have no role argument. Different Type values must not
	// duplicate the same native restoration or its retained byte buffer.
	want := map[string]int{
		fmt.Sprintf("file:%s:%d", configured.Path, ckalkan.CertCA):           1,
		fmt.Sprintf("file:%s:%d", configured.Path, ckalkan.CertIntermediate): 1,
		fmt.Sprintf("buffer:runtime certificate:%d", ckalkan.CertPEM):        1,
		fmt.Sprintf("buffer:runtime certificate:%d", ckalkan.CertDER):        1,
	}
	for range 2 {
		if err := client.LoadKeyStore(context.Background(), KeyStore{Path: "/tmp/key.p12"}); err != nil {
			t.Fatalf("LoadKeyStore: %v", err)
		}
		if !reflect.DeepEqual(loads, want) {
			t.Fatalf("restored certificate loads = %v, want %v", loads, want)
		}
	}
}

func TestFailedTrustedCertificateLoadIsNotRemembered(t *testing.T) {
	failure := &ckalkan.KalkanError{Code: ckalkan.ErrorCertParse}
	native := &fakeNative{
		loadCertBufferFunc: func([]byte, ckalkan.CertFormat) error { return failure },
		loadCertFileFunc:   func(string, ckalkan.CertType) error { return failure },
	}
	client := &Client{library: native}
	for _, cert := range []TrustedCertificate{
		{Path: "/tmp/invalid.pem", Type: CertificateCA},
		{Data: []byte("invalid"), Type: CertificateIntermediate, Format: CertificatePEM},
	} {
		err := client.LoadTrustedCertificate(context.Background(), cert)
		if !errors.Is(err, failure) || len(client.trusted) != 0 {
			t.Fatalf("failed load: err=%v retained=%d, want native failure and no retained certificate", err, len(client.trusted))
		}
	}
}

func TestKeyStoreTrustRestorationFailures(t *testing.T) {
	nativeFailure := &ckalkan.KalkanError{Code: ckalkan.ErrorCertNotFound}
	keyFailure := errors.New("key load failed")
	var keyErr error
	var failRestore bool
	var calls []string
	native := &fakeNative{
		loadKeyStoreFunc: func(ckalkan.Store, string, string, string) error {
			calls = append(calls, "key")
			return keyErr
		},
		loadCertBufferFunc: func(data []byte, _ ckalkan.CertFormat) error {
			calls = append(calls, string(data))
			if failRestore && string(data) == "second" {
				return nativeFailure
			}
			return nil
		},
	}
	client := &Client{library: native}
	for _, name := range []string{"first", "second", "third"} {
		if err := client.LoadTrustedCertificate(context.Background(), TrustedCertificate{Data: []byte(name)}); err != nil {
			t.Fatalf("initial certificate load: %v", err)
		}
	}

	keyErr = keyFailure
	calls = nil
	err := client.LoadKeyStore(context.Background(), KeyStore{Path: "/tmp/key.p12"})
	if !errors.Is(err, keyFailure) || !reflect.DeepEqual(calls, []string{"key"}) {
		t.Fatalf("failed key load: err=%v calls=%v, want original error without restoration", err, calls)
	}

	keyErr, failRestore, calls = nil, true, nil
	err = client.LoadKeyStore(context.Background(), KeyStore{Path: "/tmp/key.p12"})
	if !errors.Is(err, nativeFailure) || !strings.Contains(err.Error(), "key store loaded but restoring trusted certificate 2 failed") {
		t.Fatalf("restore error = %v, want explicit partial-success error wrapping native failure", err)
	}
	if !reflect.DeepEqual(calls, []string{"key", "first", "second"}) || len(client.trusted) != 3 {
		t.Fatalf("failed restoration calls=%v retained=%d, want stop at failure and retain full registry", calls, len(client.trusted))
	}

	failRestore, calls = false, nil
	if err := client.LoadKeyStore(context.Background(), KeyStore{Path: "/tmp/key.p12"}); err != nil {
		t.Fatalf("retry key load: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"key", "first", "second", "third"}) {
		t.Fatalf("restoration retry calls = %v", calls)
	}
}

func TestKeyStoreRestoresTrustAfterContextCanceledInsideNativeLoad(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loads := 0
	native := &fakeNative{
		loadKeyStoreFunc:   func(ckalkan.Store, string, string, string) error { cancel(); return nil },
		loadCertBufferFunc: func([]byte, ckalkan.CertFormat) error { loads++; return nil },
	}
	client := &Client{library: native}
	if err := client.LoadTrustedCertificate(ctx, TrustedCertificate{Data: []byte("certificate")}); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if err := client.LoadKeyStore(ctx, KeyStore{Path: "/tmp/key.p12"}); err != nil {
		t.Fatalf("LoadKeyStore after entering native call: %v", err)
	}
	if ctx.Err() == nil || loads != 2 {
		t.Fatalf("context error=%v certificate loads=%d, want canceled context and completed restoration", ctx.Err(), loads)
	}
}

func TestKeyStoreTrustRestorationHoldsCallGate(t *testing.T) {
	keyEntered, releaseKey := make(chan struct{}), make(chan struct{})
	restoreEntered, releaseRestore := make(chan struct{}), make(chan struct{})
	finishKey := sync.OnceFunc(func() { close(releaseKey) })
	finishRestore := sync.OnceFunc(func() { close(releaseRestore) })
	t.Cleanup(finishKey)
	t.Cleanup(finishRestore)
	hashEntered := make(chan struct{}, 1)
	var restoring bool
	native := &fakeNative{
		loadKeyStoreFunc: func(ckalkan.Store, string, string, string) error {
			restoring = true
			close(keyEntered)
			<-releaseKey
			return nil
		},
		loadCertBufferFunc: func([]byte, ckalkan.CertFormat) error {
			if restoring {
				close(restoreEntered)
				<-releaseRestore
			}
			return nil
		},
		hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
			hashEntered <- struct{}{}
			return make([]byte, 32), nil
		},
	}
	client := &Client{library: native}
	if err := client.LoadTrustedCertificate(context.Background(), TrustedCertificate{Data: []byte("certificate")}); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	keyDone := make(chan error, 1)
	go func() { keyDone <- client.LoadKeyStore(context.Background(), KeyStore{Path: "/tmp/key.p12"}) }()
	awaitTestEvent(t, keyEntered, "key-store load")
	queued := &gateWaitContext{Context: context.Background(), done: make(chan struct{}), waiting: make(chan struct{})}
	hashDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(queued, HashRequest{Algorithm: SHA256, Data: Bytes([]byte("payload"))})
		hashDone <- err
	}()
	awaitTestEvent(t, queued.waiting, "Hash gate wait")
	finishKey()
	awaitTestEvent(t, restoreEntered, "trust restoration")
	select {
	case <-hashEntered:
		t.Error("queued Hash entered native code before trust restoration completed")
	default:
	}
	finishRestore()
	if err := awaitTestEvent(t, keyDone, "key-store load result"); err != nil {
		t.Fatalf("LoadKeyStore: %v", err)
	}
	if err := awaitTestEvent(t, hashDone, "queued Hash result"); err != nil {
		t.Fatalf("queued Hash: %v", err)
	}
}

func TestCloseWaitsForTrustRestorationAndReleasesCertificates(t *testing.T) {
	restoreEntered, releaseRestore := make(chan struct{}), make(chan struct{})
	finishRestore := sync.OnceFunc(func() { close(releaseRestore) })
	t.Cleanup(finishRestore)
	closed := make(chan struct{}, 1)
	var restoring bool
	native := &fakeNative{
		loadKeyStoreFunc: func(ckalkan.Store, string, string, string) error { restoring = true; return nil },
		loadCertBufferFunc: func([]byte, ckalkan.CertFormat) error {
			if restoring {
				close(restoreEntered)
				<-releaseRestore
			}
			return nil
		},
		closeFunc: func() error { closed <- struct{}{}; return nil },
	}
	client := &Client{library: native}
	if err := client.LoadTrustedCertificate(context.Background(), TrustedCertificate{Data: []byte("certificate")}); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	keyDone := make(chan error, 1)
	go func() { keyDone <- client.LoadKeyStore(context.Background(), KeyStore{Path: "/tmp/key.p12"}) }()
	awaitTestEvent(t, restoreEntered, "trust restoration")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.CloseContext(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("CloseContext = %v, want context cancellation while restoration runs", err)
	}
	select {
	case <-closed:
		t.Error("native Close ran before trust restoration completed")
	default:
	}
	finishRestore()
	if err := awaitTestEvent(t, keyDone, "key-store load result"); err != nil {
		t.Fatalf("in-flight LoadKeyStore: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if client.trusted != nil {
		t.Fatal("Close retained trusted certificate memory")
	}
}

func TestTrustedCertificateOptionSupportsConcurrentOpen(t *testing.T) {
	data := []byte("shared option data")
	options := []Option{WithLibraryPath(testLibraryPath()), WithTrustedCertificate(TrustedCertificate{Data: data})}
	type opened struct {
		client *Client
		err    error
	}
	results := make(chan opened, 4)
	for range cap(results) {
		go func() {
			client, err := openWithLibraryFactory(context.Background(), options, func(config) (closer, error) {
				return &fakeNative{loadCertBufferFunc: func([]byte, ckalkan.CertFormat) error { return nil }}, nil
			})
			results <- opened{client, err}
		}()
	}
	clients := make([]*Client, 0, cap(results))
	for range cap(results) {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent Open: %v", result.err)
		}
		clients = append(clients, result.client)
		defer result.client.Close()
	}
	for i, client := range clients {
		if sameByteSliceBacking(client.trusted[0].data, data) {
			t.Fatal("client retained shared option data")
		}
		for _, previous := range clients[:i] {
			if sameByteSliceBacking(client.trusted[0].data, previous.trusted[0].data) {
				t.Fatal("concurrent clients share their retained certificate buffer")
			}
		}
	}
	if string(data) != "shared option data" {
		t.Fatal("Open mutated the option's caller-owned data")
	}
}

type keyStoreOnlyNative struct{ loads int }

func (native *keyStoreOnlyNative) Close() error { return nil }
func (native *keyStoreOnlyNative) LoadKeyStore(ckalkan.Store, string, string, string) error {
	native.loads++
	return nil
}

func TestKeyStoreWithoutTrustDoesNotRequireCertificateCapability(t *testing.T) {
	native := &keyStoreOnlyNative{}
	client := &Client{library: native}
	if err := client.LoadKeyStore(context.Background(), KeyStore{Path: "/tmp/key.p12"}); err != nil || native.loads != 1 {
		t.Fatalf("LoadKeyStore = %v, native calls=%d, want successful key-store-only operation", err, native.loads)
	}
}
