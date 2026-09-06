package isolated

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/kalkan"
)

type lifecycleClient struct {
	sdkClient
	closeCalls int
}

func (c *lifecycleClient) Close() error {
	c.closeCalls++
	return nil
}

func TestMalformedLifecycleRequestsDoNotReachSDK(t *testing.T) {
	for _, test := range []struct {
		operation string
		payload   []byte
	}{
		{"Open", nil},
		{"Close", []byte{1}},
	} {
		t.Run(test.operation, func(t *testing.T) {
			client := &lifecycleClient{}
			openCalls := 0
			factory := func(context.Context, libraryConfig, kalkan.Observer) (workerSession, error) {
				openCalls++
				return client, nil
			}
			var session workerSession
			if test.operation == "Close" {
				session = client
			}
			result := execute(message{
				ID: 2, Operation: test.operation, Payload: wirePayload{metadata: test.payload},
			}, session, factory, nil)
			if err := result.message.Error; !errors.Is(err, ErrProtocol) || !result.quit {
				t.Fatalf("execute = %v, quit=%t; want terminal protocol error", err, result.quit)
			}
			if openCalls != 0 || client.closeCalls != 0 {
				t.Fatalf("malformed request reached SDK: Open=%d, Close=%d", openCalls, client.closeCalls)
			}
		})
	}
}

// Invalid SDK configuration is rejected inside RunWorker before native loading.
// This checks the public same-executable path even on machines without the SDK.
func TestRunWorkerReturnsSDKValidationError(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	emptyTSA := ""
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := Open(ctx, Config{
		WorkerPath:  executable,
		WorkerArgs:  []string{"-test.run=^TestSDKWorkerHelper$", "--", "kalkan-sdk-worker"},
		LibraryPath: filepath.Join(t.TempDir(), "unused-library"),
		TSAURL:      &emptyTSA,
	})
	if client != nil {
		_ = client.Close()
		t.Fatal("Open succeeded with an empty TSA URL")
	}
	if !errors.Is(err, kalkan.ErrInvalidInput) {
		t.Fatalf("Open = %v, want SDK validation error returned by RunWorker", err)
	}
}

// The native worker lives in this test executable, using the public entry point.
func TestSDKWorkerHelper(t *testing.T) {
	if len(os.Args) != 4 || os.Args[2] != "--" || os.Args[3] != "kalkan-sdk-worker" {
		return
	}
	if err := RunWorker(context.Background()); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
