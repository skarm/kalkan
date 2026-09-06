//go:build linux || darwin || windows

package isolated

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
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

func TestBlockedWorkerResponseStopsOnCancellationAndEOF(t *testing.T) {
	for _, eof := range []bool{false, true} {
		name := "cancellation"
		want := context.Canceled
		if eof {
			name, want = "request EOF", io.EOF
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transport, parent := workerTestPipes(t)
				writer := &notifiedWorkerWriter{WriteCloser: transport.writer, started: make(chan struct{}), finished: make(chan struct{})}
				transport.writer = writer
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					done <- serve(ctx, transport, func(context.Context, libraryConfig, kalkan.Observer) (workerSession, error) {
						return &lifecycleClient{}, nil
					})
				}()
				writeWorkerOpen(t, parent)
				<-writer.started
				synctest.Wait()
				if eof {
					if err := parent.writer.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					cancel()
				}
				if err := <-done; !errors.Is(err, want) {
					t.Fatalf("serve = %v, want %v", err, want)
				}
				select {
				case <-writer.finished:
				default:
					t.Fatal("serve returned before its blocked response writer exited")
				}
			})
		})
	}
}

func TestWorkerAcceptsNextRequestBeforeWriterCompletion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport, parent := workerTestPipes(t)
		release := make(chan struct{})
		transport.writer = &pausedWorkerWriter{WriteCloser: transport.writer, release: release, stopped: make(chan struct{})}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		client := &lifecycleClient{}
		done := make(chan error, 1)
		go func() {
			done <- serve(ctx, transport, func(context.Context, libraryConfig, kalkan.Observer) (workerSession, error) {
				return client, nil
			})
		}()
		writeWorkerOpen(t, parent)
		if response, err := readMessage(parent); err != nil || response.Operation != opOpen || response.Error != nil {
			t.Fatalf("Open response = %+v, %v", response, err)
		}
		if err := writeMessage(parent, message{ID: 2, Operation: opClose}); err != nil {
			t.Fatal(err)
		}
		// The entire response reached the parent, but Write has not returned.
		// Let the server receive and retain the next request in this interval.
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("valid next request was rejected before writer completion: %v", err)
		default:
		}
		close(release)
		if response, err := readMessage(parent); err != nil || response.Operation != opClose || response.Error != nil {
			t.Fatalf("Close response = %+v, %v", response, err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if client.closeCalls != 1 {
			t.Fatalf("Close calls = %d, want 1", client.closeCalls)
		}
	})
}

func TestWorkerRejectsRequestDuringNativeExecution(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport, parent := workerTestPipes(t)
		entered, release := make(chan struct{}), make(chan struct{})
		defer close(release)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- serve(ctx, transport, func(context.Context, libraryConfig, kalkan.Observer) (workerSession, error) {
				close(entered)
				<-release
				return &lifecycleClient{}, nil
			})
		}()
		writeWorkerOpen(t, parent)
		<-entered
		if err := writeMessage(parent, message{ID: 2, Operation: opClose}); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, ErrProtocol) {
			t.Fatalf("pipelined request = %v, want ErrProtocol", err)
		}
	})
}

func workerTestPipes(t *testing.T) (*streams, *streams) {
	t.Helper()
	requestReader, requestWriter := io.Pipe()
	responseReader, responseWriter := io.Pipe()
	transport := &streams{reader: requestReader, writer: responseWriter}
	parent := &streams{reader: responseReader, writer: requestWriter}
	t.Cleanup(func() { _ = transport.Close(); _ = parent.Close() })
	return transport, parent
}

func writeWorkerOpen(t *testing.T, writer io.Writer) {
	t.Helper()
	payload, err := encodeConfig(libraryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMessage(writer, message{ID: 1, Operation: opOpen, Payload: payload}); err != nil {
		t.Fatal(err)
	}
}

type notifiedWorkerWriter struct {
	io.WriteCloser
	once              sync.Once
	started, finished chan struct{}
}

func (w *notifiedWorkerWriter) Write(data []byte) (int, error) {
	first := false
	w.once.Do(func() { first = true; close(w.started) })
	if first {
		defer close(w.finished)
	}
	return w.WriteCloser.Write(data)
}

type pausedWorkerWriter struct {
	io.WriteCloser
	writes  int
	release <-chan struct{}
	stopped chan struct{}
	once    sync.Once
}

func (w *pausedWorkerWriter) Write(data []byte) (int, error) {
	n, err := w.WriteCloser.Write(data)
	w.writes++
	// Open's empty acknowledgement has a prefix and header, without blocks.
	if w.writes == 2 && err == nil {
		select {
		case <-w.release:
		case <-w.stopped:
			return n, io.ErrClosedPipe
		}
	}
	return n, err
}

func (w *pausedWorkerWriter) Close() error {
	w.once.Do(func() { close(w.stopped) })
	return w.WriteCloser.Close()
}

func TestDuplicatedProtocolPipeCloseInterruptsIO(t *testing.T) {
	if runtime.GOOS == "windows" && runtime.GOARCH != "amd64" {
		t.Skip("protocol pipe close regression requires windows/amd64")
	}

	for _, writing := range []bool{false, true} {
		name := "read"
		if writing {
			name = "write"
		}
		t.Run(name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			original := reader
			if writing {
				original = writer
			}
			duplicate, err := duplicateFile(original)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				// Release the peer first if a regression prevented cancellation,
				// so cleanup cannot strand a synchronous Windows pipe operation.
				_ = reader.Close()
				_ = writer.Close()
				_ = duplicate.Close()
			}()
			if runtime.GOOS != "windows" {
				// POSIX duplicates must join the runtime poller. Windows uses
				// CancelIoEx on synchronous anonymous pipes when closing them.
				if err := duplicate.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatalf("duplicate is not pollable: %v", err)
				}
			}
			started := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				close(started)
				var err error
				if writing {
					_, err = duplicate.Write(make([]byte, 8<<20))
				} else {
					_, err = duplicate.Read(make([]byte, 1))
				}
				done <- err
			}()
			<-started
			if writing {
				// Confirm that the large write is in progress without draining
				// enough bytes for it to finish before Close.
				progress := make(chan error, 1)
				go func() {
					_, err := reader.Read(make([]byte, 1))
					progress <- err
				}()
				select {
				case err := <-progress:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("duplicate write did not reach the pipe")
				}
			}
			closed := make(chan error, 1)
			go func() { closed <- duplicate.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("duplicate Close blocked during %s", name)
			}
			select {
			case err := <-done:
				if !errors.Is(err, os.ErrClosed) {
					t.Fatalf("interrupted %s = %v, want os.ErrClosed", name, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("duplicate Close did not interrupt %s", name)
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
