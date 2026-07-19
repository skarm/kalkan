package kalkan

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestOpenUsesBackgroundForNilContext(t *testing.T) {
	var initCalls int

	client, err := openWithLibraryFactory(nil, []Option{ //nolint:staticcheck
		WithLibraryPath(testLibraryPath()),
	}, func(config) (closer, error) {
		return &fakeNative{
			initFunc: func() error {
				initCalls++
				return nil
			},
		}, nil
	})
	if err != nil {
		t.Fatalf("Open nil context error = %v, want nil", err)
	}
	defer client.Close()

	if initCalls != 1 {
		t.Fatalf("Init calls = %d, want 1", initCalls)
	}
}

func TestOpenCanceledBeforeLowLevelClientCreation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var factoryCalls int
	_, err := openWithLibraryFactory(ctx, []Option{
		WithLibraryPath(testLibraryPath()),
	}, func(config) (closer, error) {
		factoryCalls++
		return &fakeNative{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open error = %v, want context canceled", err)
	}
	if factoryCalls != 0 {
		t.Fatalf("native factory calls = %d, want 0", factoryCalls)
	}
}

func TestOpenClosesClientWhenCanceledBeforeInit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var initCalls int
	var closeCalls int

	_, err := openWithLibraryFactory(ctx, []Option{
		WithLibraryPath(testLibraryPath()),
	}, func(config) (closer, error) {
		cancel()
		return &fakeNative{
			initFunc: func() error {
				initCalls++
				return nil
			},
			closeFunc: func() error {
				closeCalls++
				return nil
			},
		}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open error = %v, want context canceled", err)
	}
	if initCalls != 0 {
		t.Fatalf("Init calls = %d, want 0", initCalls)
	}
	if closeCalls != 1 {
		t.Fatalf("Close calls = %d, want cleanup close", closeCalls)
	}
}

func TestOpenJoinsCloseErrorAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	closeErr := errors.New("close failed")

	_, err := openWithLibraryFactory(ctx, []Option{
		WithLibraryPath(testLibraryPath()),
	}, func(config) (closer, error) {
		return &fakeNative{
			initFunc: func() error {
				cancel()
				return nil
			},
			closeFunc: func() error {
				return closeErr
			},
		}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open error = %v, want context canceled", err)
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("Open error = %v, want joined close error", err)
	}
}

func TestOpenCanceledAfterSetTSAURLClosesClientBeforeProxy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var proxyCalls int
	var closeCalls int

	_, err := openWithLibraryFactory(ctx, []Option{
		WithLibraryPath(testLibraryPath()),
		WithTSAURL("http://tsa.example"),
		WithProxy(Proxy{Enabled: true, Address: "127.0.0.1", Port: "3128"}),
	}, func(config) (closer, error) {
		return &fakeNative{
			setTSAURLFunc: func(tsaURL string) error {
				cancel()
				return nil
			},
			setProxyFunc: func(req ckalkan.ProxyRequest) error {
				proxyCalls++
				return nil
			},
			closeFunc: func() error {
				closeCalls++
				return nil
			},
		}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open error = %v, want context canceled", err)
	}
	if proxyCalls != 0 {
		t.Fatalf("SetProxy calls = %d, want 0 after cancellation", proxyCalls)
	}
	if closeCalls != 1 {
		t.Fatalf("Close calls = %d, want cleanup close", closeCalls)
	}
}

func TestOpenClosesClientWhenCanceledAfterProxy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var loadCalls int
	var closeCalls int

	_, err := openWithLibraryFactory(ctx, []Option{
		WithLibraryPath(testLibraryPath()),
		WithProxy(Proxy{Enabled: true, Address: "127.0.0.1", Port: "3128"}),
		WithTrustedCertificate(TrustedCertificate{Data: []byte("trusted"), Type: CertificateCA, Format: CertificatePEM}),
	}, func(config) (closer, error) {
		return &fakeNative{
			setProxyFunc: func(req ckalkan.ProxyRequest) error {
				cancel()
				return nil
			},
			loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
				loadCalls++
				return nil
			},
			closeFunc: func() error {
				closeCalls++
				return nil
			},
		}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open error = %v, want context canceled", err)
	}
	if loadCalls != 0 {
		t.Fatalf("trusted cert loads = %d, want 0 after cancellation", loadCalls)
	}
	if closeCalls != 1 {
		t.Fatalf("Close calls = %d, want cleanup close", closeCalls)
	}
}

func TestOpenClosesClientWhenCanceledDuringCertificateLoad(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var loadCalls int
	var closeCalls int

	_, err := openWithLibraryFactory(ctx, []Option{
		WithLibraryPath(testLibraryPath()),
		WithTrustedCertificate(TrustedCertificate{Data: []byte("first"), Type: CertificateCA, Format: CertificatePEM}),
		WithTrustedCertificate(TrustedCertificate{Data: []byte("second"), Type: CertificateCA, Format: CertificatePEM}),
	}, func(config) (closer, error) {
		return &fakeNative{
			loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
				loadCalls++
				cancel()
				return nil
			},
			closeFunc: func() error {
				closeCalls++
				return nil
			},
		}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open error = %v, want context canceled", err)
	}
	if loadCalls != 1 {
		t.Fatalf("trusted cert loads = %d, want only first cert loaded", loadCalls)
	}
	if closeCalls != 1 {
		t.Fatalf("Close calls = %d, want cleanup close", closeCalls)
	}
}

func TestCloseWaitsForInFlightNativeCall(t *testing.T) {
	enteredHash := make(chan struct{})
	releaseHash := make(chan struct{})
	closeCalled := make(chan struct{})
	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			close(enteredHash)
			<-releaseHash
			return []byte("digest"), nil
		},
		closeFunc: func() error {
			close(closeCalled)
			return nil
		},
	}
	client := &Client{library: native}

	hashDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{
			Data: Bytes([]byte("payload")),
		})
		hashDone <- err
	}()

	<-enteredHash
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- client.Close()
	}()

	select {
	case <-closeCalled:
		t.Fatal("Close reached native Close while another native call was in flight")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseHash)
	if err := <-hashDone; err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if _, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("payload"))}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Hash after Close error = %v, want closed client error", err)
	}
}

func TestCloseContextTimesOutDuringNativeCall(t *testing.T) {
	enteredHash := make(chan struct{})
	releaseHash := make(chan struct{})
	closeCalled := make(chan struct{})
	var closeCalls atomic.Int32

	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			close(enteredHash)
			<-releaseHash
			return []byte("digest"), nil
		},
		closeFunc: func() error {
			closeCalls.Add(1)
			close(closeCalled)
			return nil
		},
	}
	client := &Client{library: native}

	hashDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{
			Data: Bytes([]byte("payload")),
		})
		hashDone <- err
	}()

	<-enteredHash

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	if err := client.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext error = %v, want context deadline exceeded", err)
	}
	if got := closeCalls.Load(); got != 0 {
		t.Fatalf("native Close calls before gate release = %d, want 0", got)
	}

	select {
	case <-closeCalled:
		t.Fatal("CloseContext reached native Close before the in-flight native call completed")
	default:
	}

	close(releaseHash)
	if err := <-hashDone; err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	select {
	case <-closeCalled:
	case <-time.After(time.Second):
		t.Fatal("native Close was not called after the in-flight native call completed")
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("native Close calls = %d, want 1", got)
	}
	if _, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("payload"))}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Hash after CloseContext error = %v, want closed client error", err)
	}
}

func TestCloseContextTimesOutDuringConcurrentClose(t *testing.T) {
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	native := &fakeNative{
		closeFunc: func() error {
			close(closeStarted)
			<-releaseClose
			return nil
		},
	}
	client := &Client{library: native}

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- client.Close()
	}()
	<-closeStarted

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	if err := client.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext while Close is running error = %v, want context deadline exceeded", err)
	}

	close(releaseClose)
	if err := <-firstDone; err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestCloseRejectsQueuedOperationAfterCloseBegins(t *testing.T) {
	closeDone := make(chan error, 1)
	hashDone := make(chan error, 1)
	hashWaitingForGate := make(chan struct{})
	var calls atomic.Int32

	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			t.Fatal("queued Hash started after Close began")
			calls.Add(1)
			return nil, nil
		},
		closeFunc: func() error {
			return nil
		},
	}
	client := &Client{
		gate:    make(chan struct{}, 1),
		library: native,
	}
	ctx := &gateWaitContext{
		Context: context.Background(),
		done:    make(chan struct{}),
		waiting: hashWaitingForGate,
	}

	go func() {
		_, err := client.Hash(ctx, HashRequest{Data: Bytes([]byte("queued"))})
		hashDone <- err
	}()
	<-hashWaitingForGate

	go func() {
		closeDone <- client.Close()
	}()
	waitForClientClosing(t, client)

	client.gate <- struct{}{}

	if err := <-hashDone; !errors.Is(err, ErrClosed) {
		t.Fatalf("queued Hash error = %v, want closed client error", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("native HashData calls = %d, want 0", got)
	}
}

func TestCloseRejectsNewOperationAfterCloseBegins(t *testing.T) {
	enteredHash := make(chan struct{})
	releaseHash := make(chan struct{})
	closeDone := make(chan error, 1)
	var calls atomic.Int32

	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			calls.Add(1)
			close(enteredHash)
			<-releaseHash
			return []byte("digest"), nil
		},
		closeFunc: func() error {
			return nil
		},
	}
	client := &Client{library: native}

	firstDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("first"))})
		firstDone <- err
	}()
	<-enteredHash

	go func() {
		closeDone <- client.Close()
	}()
	waitForClientClosed(t, client)

	_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("second"))})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Hash after Close began error = %v, want closed client error", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("native HashData calls = %d, want only in-flight call", got)
	}

	close(releaseHash)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Hash returned error: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestConcurrentCloseCallsCloseNativeOnce(t *testing.T) {
	var closeCalls atomic.Int32
	native := &fakeNative{
		closeFunc: func() error {
			closeCalls.Add(1)
			time.Sleep(10 * time.Millisecond)
			return nil
		},
	}
	client := &Client{library: native}

	const goroutines = 8
	start := make(chan struct{})
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start
			errs <- client.Close()
		}()
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("native Close calls = %d, want 1", got)
	}
}

func TestConcurrentCloseWaitsForNativeCloseToFinish(t *testing.T) {
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	var closeCalls atomic.Int32
	native := &fakeNative{
		closeFunc: func() error {
			closeCalls.Add(1)
			close(closeStarted)
			<-releaseClose
			return nil
		},
	}
	client := &Client{library: native}

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- client.Close()
	}()
	<-closeStarted

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- client.Close()
	}()

	select {
	case err := <-secondDone:
		t.Fatalf("concurrent Close returned before native Close finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseClose)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("native Close calls = %d, want 1", got)
	}
}

func TestOpenSetupNativeCallsWaitForExistingNativeGate(t *testing.T) {
	gate := make(chan struct{}, 1)
	initStarted := make(chan struct{})
	native := &fakeNative{
		initFunc: func() error {
			close(initStarted)
			return nil
		},
	}
	client := &Client{gate: gate, library: native}

	openDone := make(chan error, 1)
	go func() {
		openDone <- setupOpenedClient(context.Background(), client, defaultOpenConfig())
	}()

	select {
	case <-initStarted:
		t.Fatal("Open reached native setup call while another native call held the gate")
	case <-time.After(50 * time.Millisecond):
	}

	gate <- struct{}{}
	if err := <-openDone; err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
}

func TestLockNativeHonorsContextWhileWaiting(t *testing.T) {
	enteredHash := make(chan struct{})
	releaseHash := make(chan struct{})
	var calls atomic.Int32

	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			if calls.Add(1) == 1 {
				close(enteredHash)
			}
			<-releaseHash
			return []byte("digest"), nil
		},
	}
	client := &Client{library: native}

	firstDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{
			Data: Bytes([]byte("first")),
		})
		firstDone <- err
	}()

	<-enteredHash

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.Hash(ctx, HashRequest{
		Data: Bytes([]byte("second")),
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Hash while waiting for native lock error = %v, want context deadline", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("native HashData calls = %d, want only the in-flight call", got)
	}

	close(releaseHash)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Hash returned error: %v", err)
	}
}

func TestClientMethodUsesBackgroundForNilContext(t *testing.T) {
	client := &Client{
		library: &fakeNative{
			hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
				return []byte("digest"), nil
			},
		},
	}

	digest, err := client.Hash(nil, HashRequest{Data: Bytes([]byte("payload"))}) //nolint:staticcheck
	if err != nil {
		t.Fatalf("Hash nil context error = %v, want nil", err)
	}
	if string(digest.Data) != "digest" {
		t.Fatalf("Hash digest = %q, want digest", digest.Data)
	}
}

func TestClientMethodsHonorCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	native := &fakeNative{
		hashDataFunc: func(algorithm ckalkan.HashAlgorithm, flags ckalkan.Flag, data []byte) ([]byte, error) {
			t.Error("Hash called native after context cancellation")
			return nil, nil
		},
		signHashFunc: func(alias string, flags ckalkan.Flag, hash []byte) ([]byte, error) {
			t.Error("SignHash called native after context cancellation")
			return nil, nil
		},
		signDataFunc: func(alias string, flags ckalkan.Flag, data, signature []byte) ([]byte, error) {
			t.Error("CMS method called native after context cancellation")
			return nil, nil
		},
		verifyDataFunc: func(req ckalkan.VerifyDataRequest) (ckalkan.VerifyDataResult, error) {
			t.Error("VerifyCMS called native after context cancellation")
			return ckalkan.VerifyDataResult{}, nil
		},
		signXMLFunc: func(req ckalkan.SignXMLRequest) ([]byte, error) {
			t.Error("SignXML called native after context cancellation")
			return nil, nil
		},
		verifyXMLFunc: func(alias string, flags ckalkan.Flag, xml []byte) (string, error) {
			t.Error("VerifyXML called native after context cancellation")
			return "", nil
		},
		signWSSEFunc: func(req ckalkan.SignWSSERequest) ([]byte, error) {
			t.Error("SignWSSE called native after context cancellation")
			return nil, nil
		},
		loadKeyStoreFunc: func(storage ckalkan.Store, password, container, alias string) error {
			t.Error("LoadKeyStore called native after context cancellation")
			return nil
		},
		loadCertBufferFunc: func(cert []byte, format ckalkan.CertFormat) error {
			t.Error("LoadTrustedCertificate called native after context cancellation")
			return nil
		},
		validateCertificateFunc: func(req ckalkan.ValidateCertificateRequest) (ckalkan.ValidateCertificateResult, error) {
			t.Error("ValidateCertificate called native after context cancellation")
			return ckalkan.ValidateCertificateResult{}, nil
		},
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			t.Error("SignZIP called native after context cancellation")
			return nil
		},
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			t.Error("VerifyZIP called native after context cancellation")
			return "", nil
		},
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			t.Error("ExtractZIPSignerCertificate called native after context cancellation")
			return nil, nil
		},
	}
	client := &Client{library: native}

	tests := []struct {
		name string
		call func() error
	}{
		{name: "Hash", call: func() error {
			_, err := client.Hash(ctx, HashRequest{})
			return err
		}},
		{name: "SignHash", call: func() error {
			_, err := client.SignHash(ctx, SignHashRequest{})
			return err
		}},
		{name: "SignCMS", call: func() error {
			_, err := client.SignCMS(ctx, SignCMSRequest{})
			return err
		}},
		{name: "VerifyCMS", call: func() error {
			_, err := client.VerifyCMS(ctx, VerifyCMSRequest{})
			return err
		}},
		{name: "SignXML", call: func() error {
			_, err := client.SignXML(ctx, SignXMLRequest{})
			return err
		}},
		{name: "VerifyXML", call: func() error {
			_, err := client.VerifyXML(ctx, VerifyXMLRequest{})
			return err
		}},
		{name: "SignWSSE", call: func() error {
			_, err := client.SignWSSE(ctx, SignWSSERequest{})
			return err
		}},
		{name: "LoadKeyStore", call: func() error {
			return client.LoadKeyStore(ctx, KeyStore{})
		}},
		{name: "LoadTrustedCertificate", call: func() error {
			return client.LoadTrustedCertificate(ctx, TrustedCertificate{})
		}},
		{name: "ValidateCertificate", call: func() error {
			_, err := client.ValidateCertificate(ctx, ValidateCertificateRequest{})
			return err
		}},
		{name: "SignZIP", call: func() error {
			_, err := client.SignZIP(ctx, SignZIPRequest{})
			return err
		}},
		{name: "VerifyZIP", call: func() error {
			_, err := client.VerifyZIP(ctx, VerifyZIPRequest{})
			return err
		}},
		{name: "ExtractZIPSignerCertificate", call: func() error {
			_, err := client.ExtractZIPSignerCertificate(ctx, ExtractZIPSignerCertificateRequest{})
			return err
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, context.Canceled) {
				t.Fatalf("%s error = %v, want context.Canceled", test.name, err)
			}
		})
	}
}

func waitForClientClosed(t *testing.T, client *Client) {
	t.Helper()

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		closed := client.library == nil || client.closing != nil
		client.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(time.Millisecond)
	}

	t.Fatal("client did not enter closed state")
}

func waitForClientClosing(t *testing.T, client *Client) {
	t.Helper()

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		closing := client.closing != nil
		client.mu.Unlock()
		if closing {
			return
		}
		time.Sleep(time.Millisecond)
	}

	t.Fatal("client did not enter closing state")
}

type gateWaitContext struct {
	context.Context
	done    chan struct{}
	waiting chan struct{}
	once    sync.Once
}

func (c *gateWaitContext) Done() <-chan struct{} {
	c.once.Do(func() {
		close(c.waiting)
	})

	return c.done
}

func (c *gateWaitContext) Err() error {
	return nil
}
