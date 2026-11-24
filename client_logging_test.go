package kalkan

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestWithOperationsLoggingDoesNotHoldNativeGate(t *testing.T) {
	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	secondNativeCall := make(chan struct{})
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}()

	var handled atomic.Int32
	handler := &callbackSlogHandler{
		handle: func(context.Context, slog.Record) error {
			if handled.Add(1) == 1 {
				close(handlerEntered)
				<-releaseHandler
			}

			return nil
		},
	}

	var nativeCalls atomic.Int32
	client := &Client{
		session: newNativeBackend(&fakeSDK{
			initFunc: func() error {
				if nativeCalls.Add(1) == 2 {
					close(secondNativeCall)
				}

				return nil
			},
		}),
		logger: slog.New(handler),
	}

	call := func() error {
		return withOperations(client, context.Background(), "Init", func(native sessionInitializer) error {
			return native.Init()
		})
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- call() }()
	awaitTestEvent(t, handlerEntered, "first logger invocation")

	secondDone := make(chan error, 1)
	go func() { secondDone <- call() }()
	awaitTestEvent(t, secondNativeCall, "second native call while the first logger is blocked")
	if err := awaitTestEvent(t, secondDone, "second helper result"); err != nil {
		t.Fatalf("second helper call returned error: %v", err)
	}

	releaseOnce.Do(func() { close(releaseHandler) })
	if err := awaitTestEvent(t, firstDone, "first helper result"); err != nil {
		t.Fatalf("first helper call returned error: %v", err)
	}
}

func TestWithOperationsResultLoggingDoesNotHoldNativeGate(t *testing.T) {
	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	secondNativeCall := make(chan struct{})
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}()

	var handled atomic.Int32
	handler := &callbackSlogHandler{
		handle: func(context.Context, slog.Record) error {
			if handled.Add(1) == 1 {
				close(handlerEntered)
				<-releaseHandler
			}

			return nil
		},
	}

	var nativeCalls atomic.Int32
	client := &Client{
		session: newNativeBackend(&fakeSDK{
			hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
				call := nativeCalls.Add(1)
				if call == 2 {
					close(secondNativeCall)
				}

				return []byte{byte(call)}, nil
			},
		}),
		logger: slog.New(handler),
	}

	call := func() ([]byte, error) {
		return withOperationsResult(client, context.Background(), "Hash", func(native hashOperations) ([]byte, error) {
			return native.HashData(ckalkan.SHA256, 0, []byte("payload"))
		})
	}

	firstDone := make(chan bytesResult, 1)
	go func() {
		result, err := call()
		firstDone <- bytesResult{result: result, err: err}
	}()
	awaitTestEvent(t, handlerEntered, "first result logger invocation")

	secondDone := make(chan bytesResult, 1)
	go func() {
		result, err := call()
		secondDone <- bytesResult{result: result, err: err}
	}()
	awaitTestEvent(t, secondNativeCall, "second result-returning native call while the first logger is blocked")

	second := awaitTestEvent(t, secondDone, "second result-returning helper result")
	if second.err != nil {
		t.Fatalf("second helper call returned error: %v", second.err)
	}
	if len(second.result) != 1 || second.result[0] != 2 {
		t.Fatalf("second helper result = %v, want [2]", second.result)
	}

	releaseOnce.Do(func() { close(releaseHandler) })
	first := awaitTestEvent(t, firstDone, "first result-returning helper result")
	if first.err != nil {
		t.Fatalf("first helper call returned error: %v", first.err)
	}
	if len(first.result) != 1 || first.result[0] != 1 {
		t.Fatalf("first helper result = %v, want [1]", first.result)
	}
}

func TestReentrantLoggerCanCallClientMethod(t *testing.T) {
	var nativeCalls atomic.Int32
	client := &Client{
		session: newNativeBackend(&fakeSDK{
			hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
				return []byte{byte(nativeCalls.Add(1))}, nil
			},
		}),
	}

	reentrantDone := make(chan error, 1)
	var reentered atomic.Bool
	client.logger = slog.New(&callbackSlogHandler{
		handle: func(context.Context, slog.Record) error {
			if !reentered.CompareAndSwap(false, true) {
				return nil
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			_, err := client.Hash(ctx, HashRequest{Data: Bytes([]byte("reentrant"))})
			reentrantDone <- err

			return nil
		},
	})

	outerDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("outer"))})
		outerDone <- err
	}()

	if err := awaitTestEvent(t, reentrantDone, "reentrant client call"); err != nil {
		t.Fatalf("reentrant Hash returned error: %v", err)
	}
	if err := awaitTestEvent(t, outerDone, "outer client call"); err != nil {
		t.Fatalf("outer Hash returned error: %v", err)
	}
	if got := nativeCalls.Load(); got != 2 {
		t.Fatalf("native calls = %d, want 2", got)
	}
}

func TestNativeCallErrorIsLoggedAfterGateRelease(t *testing.T) {
	nativeErr := errors.New("native hash failed")
	handlerEntered := make(chan loggedNativeCall, 1)
	releaseHandler := make(chan struct{})
	secondNativeCall := make(chan struct{})
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}()

	var handled atomic.Int32
	handler := &callbackSlogHandler{
		handle: func(_ context.Context, record slog.Record) error {
			if handled.Add(1) != 1 {
				return nil
			}

			logged := loggedNativeCall{level: record.Level, message: record.Message}
			record.Attrs(func(attr slog.Attr) bool {
				switch attr.Key {
				case "operation":
					logged.operation = attr.Value.String()
				case "error_class":
					logged.errorClass = attr.Value.String()
				case "error":
					t.Error("logger received raw error data")
				}

				return true
			})
			handlerEntered <- logged
			<-releaseHandler

			return nil
		},
	}

	var nativeCalls atomic.Int32
	client := &Client{
		session: newNativeBackend(&fakeSDK{
			hashDataFunc: func(ckalkan.HashAlgorithm, ckalkan.Flag, []byte) ([]byte, error) {
				if nativeCalls.Add(1) == 1 {
					return nil, nativeErr
				}

				close(secondNativeCall)

				return []byte("digest"), nil
			},
		}),
		logger: slog.New(handler),
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("first"))})
		firstDone <- err
	}()

	logged := awaitTestEvent(t, handlerEntered, "native error log")
	if logged.level != slog.LevelError || logged.message != "kalkan operation failed" || logged.operation != "Hash" {
		t.Fatalf("logged native call = %+v", logged)
	}
	if logged.errorClass != "operation_failure" {
		t.Fatalf("logged error class = %q, want operation_failure", logged.errorClass)
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := client.Hash(context.Background(), HashRequest{Data: Bytes([]byte("second"))})
		secondDone <- err
	}()
	awaitTestEvent(t, secondNativeCall, "native call after logged error")
	if err := awaitTestEvent(t, secondDone, "operation after logged error"); err != nil {
		t.Fatalf("second Hash returned error: %v", err)
	}

	releaseOnce.Do(func() { close(releaseHandler) })
	if err := awaitTestEvent(t, firstDone, "failed operation result"); !errors.Is(err, nativeErr) {
		t.Fatalf("first Hash error = %v, want %v", err, nativeErr)
	}
}

func TestNativeCallbackPanicReleasesGate(t *testing.T) {
	panicValue := errors.New("fake native panic")
	var nativeCalls atomic.Int32
	client := &Client{
		session: newNativeBackend(&fakeSDK{
			initFunc: func() error {
				if nativeCalls.Add(1) == 1 {
					panic(panicValue)
				}

				return nil
			},
		}),
	}

	var recovered any
	func() {
		defer func() { recovered = recover() }()

		_ = withOperations(client, context.Background(), "Init", func(native sessionInitializer) error {
			return native.Init()
		})
	}()
	recoveredErr, ok := recovered.(error)
	if !ok || !errors.Is(recoveredErr, panicValue) {
		t.Fatalf("recovered panic = %v, want %v", recovered, panicValue)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := withOperations(client, ctx, "Init", func(native sessionInitializer) error {
		return native.Init()
	}); err != nil {
		t.Fatalf("helper call after panic returned error: %v", err)
	}
	if got := nativeCalls.Load(); got != 2 {
		t.Fatalf("native calls = %d, want 2", got)
	}
}

func TestCloseContextCompletesBeforeSlowLogger(t *testing.T) {
	handlerEntered := make(chan struct{})
	handlerExited := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}()

	handler := &callbackSlogHandler{
		handle: func(_ context.Context, record slog.Record) error {
			var operation string
			record.Attrs(func(attr slog.Attr) bool {
				if attr.Key == "operation" {
					operation = attr.Value.String()
				}

				return true
			})
			if operation != "Close" {
				return nil
			}

			close(handlerEntered)
			<-releaseHandler
			close(handlerExited)

			return nil
		},
	}
	client := &Client{
		session: newNativeBackend(&fakeSDK{}),
		logger:  slog.New(handler),
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.CloseContext(context.Background()) }()
	awaitTestEvent(t, handlerEntered, "Close logger invocation")

	if err := awaitTestEvent(t, closeDone, "CloseContext lifecycle completion"); err != nil {
		t.Fatalf("CloseContext returned error: %v", err)
	}

	select {
	case <-client.gate:
		client.gate <- struct{}{}
	case <-time.After(testEventTimeout):
		t.Fatal("native gate remained held while Close logger was blocked")
	}

	client.mu.Lock()
	session := client.session
	closing := client.closing
	client.mu.Unlock()
	if session != nil || closing == nil {
		t.Fatalf("client lifecycle after CloseContext = library %v, closing %v; want fully closed", session, closing)
	}
	select {
	case <-closing.done:
	default:
		t.Fatal("close result is not ready while logger is blocked")
	}
	if err := client.CloseContext(context.Background()); err != nil {
		t.Fatalf("repeated CloseContext returned error: %v", err)
	}

	releaseOnce.Do(func() { close(releaseHandler) })
	awaitTestEvent(t, handlerExited, "Close logger completion")
}

type bytesResult struct {
	result []byte
	err    error
}

type loggedNativeCall struct {
	level      slog.Level
	message    string
	operation  string
	errorClass string
}

type callbackSlogHandler struct {
	handle func(context.Context, slog.Record) error
}

func (h *callbackSlogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *callbackSlogHandler) Handle(ctx context.Context, record slog.Record) error {
	return h.handle(ctx, record)
}

func (h *callbackSlogHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *callbackSlogHandler) WithGroup(string) slog.Handler {
	return h
}

func TestSignerCertificateLoggingClassifiesEndOfList(t *testing.T) {
	der := testCertificateDER(t, "signer")
	for _, operation := range []string{"CMS", "XML"} {
		endCode := ckalkan.ErrorCertNotFound
		if operation == "XML" {
			endCode = ckalkan.ErrorIDAttrNotFound
		}
		for _, tc := range []struct {
			name         string
			firstMissing bool
			code         ckalkan.ErrorCode
			wantLevel    slog.Level
		}{
			{"end of list", false, endCode, slog.LevelDebug},
			{"first certificate missing", true, endCode, slog.LevelError},
			{"later native failure", false, ckalkan.ErrorSignInvalid, slog.LevelError},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				var levels []slog.Level
				fetch := func(id int) ([]byte, error) {
					firstID := 1
					if id == firstID && !tc.firstMissing {
						return der, nil
					}
					return nil, &ckalkan.KalkanError{Code: tc.code}
				}
				client := &Client{
					session: newNativeBackend(&fakeSDK{
						getCertFromCMSFunc: func(_ []byte, id int, _ ckalkan.Flag) ([]byte, error) { return fetch(id) },
						getCertFromXMLFunc: func(_ []byte, id int) ([]byte, error) { return fetch(id) },
					}),
					logger: slog.New(&callbackSlogHandler{handle: func(_ context.Context, record slog.Record) error {
						levels = append(levels, record.Level)
						return nil
					}}),
				}
				var err error
				if operation == "CMS" {
					_, err = client.GetCertFromCMS(context.Background(), Bytes([]byte("cms")))
				} else {
					_, err = client.GetCertFromXML(context.Background(), Bytes([]byte("<signed/>")))
				}
				if tc.wantLevel == slog.LevelDebug {
					if err != nil {
						t.Fatalf("end of list returned error: %v", err)
					}
				} else {
					requireKalkanErrorCode(t, err, tc.code)
				}
				wantCount := 2
				if tc.firstMissing {
					wantCount = 1
				}
				if len(levels) != wantCount || levels[len(levels)-1] != tc.wantLevel {
					t.Fatalf("levels = %v, want %d records ending in %v", levels, wantCount, tc.wantLevel)
				}
			})
		}
	}
}

func TestCertificatePropertyLoggingClassifiesOptionalAbsence(t *testing.T) {
	for _, item := range certificateInfoProperties {
		t.Run(fmt.Sprint(item.prop), func(t *testing.T) {
			var level slog.Level
			client := &Client{
				session: newNativeBackend(&fakeSDK{certificateGetInfoFunc: func(_ []byte, _ ckalkan.CertProp) ([]byte, error) {
					return nil, &ckalkan.KalkanError{Code: ckalkan.ErrorGetCertProp}
				}}),
				logger: slog.New(&callbackSlogHandler{handle: func(_ context.Context, record slog.Record) error {
					level = record.Level
					return nil
				}}),
			}
			_, err := client.X509CertificateGetInfoFields(context.Background(), &x509.Certificate{Raw: []byte("DER")}, item.field)
			want := slog.LevelError
			if item.optional {
				want = slog.LevelDebug
				if err != nil {
					t.Fatalf("optional property returned error: %v", err)
				}
			} else {
				requireKalkanErrorCode(t, err, ckalkan.ErrorGetCertProp)
			}
			if level != want {
				t.Fatalf("level = %v, want %v", level, want)
			}
		})
	}
}
