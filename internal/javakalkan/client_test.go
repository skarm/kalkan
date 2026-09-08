package javakalkan

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

// A child test process stands in for Java to exercise broken pipes, malformed
// responses and cancellation without depending on an installed vendor SDK.
func TestMain(m *testing.M) {
	if mode := os.Getenv("KALKAN_JAVA_TEST_WORKER"); mode != "" {
		runTestWorker(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runTestWorker(mode string) {
	write := func(status int32, fields ...[]byte) {
		_ = binary.Write(os.Stdout, binary.BigEndian, status)
		_ = binary.Write(os.Stdout, binary.BigEndian, int32(len(fields)))
		for _, field := range fields {
			_ = binary.Write(os.Stdout, binary.BigEndian, int32(len(field)))
			_, _ = os.Stdout.Write(field)
		}
	}
	for {
		var opcode, count int32
		if binary.Read(os.Stdin, binary.BigEndian, &opcode) != nil {
			return
		}
		if binary.Read(os.Stdin, binary.BigEndian, &count) != nil {
			return
		}
		args := make([][]byte, count)
		for i := range count {
			var size int32
			if binary.Read(os.Stdin, binary.BigEndian, &size) != nil {
				return
			}
			args[i] = make([]byte, size)
			if _, err := io.ReadFull(os.Stdin, args[i]); err != nil {
				return
			}
		}
		if mode == "exit-init" {
			return
		}
		if opcode == 0 {
			write(0, []byte("kalkan-java/1"))
			continue
		}
		if opcode == 10 {
			write(0)
			continue
		}
		if opcode == 100 {
			if string(args[0]) == "ok" {
				write(0, args[1])
			} else {
				write(3, args[1])
			}
			continue
		}
		switch mode {
		case "network":
			write(5, []byte("POST"), []byte(os.Getenv("KALKAN_JAVA_TEST_URL")), []byte("OCSP request"))
		case "hang":
			// The parent must terminate this blocked process when ctx expires.
			time.Sleep(time.Minute)
		case "oversized":
			write(4, []byte("10000"))
			mode = "ok"
		case "crypto-error":
			write(3, []byte("signature rejected"))
			mode = "ok"
		case "truncated":
			_ = binary.Write(os.Stdout, binary.BigEndian, int32(0))
			_ = binary.Write(os.Stdout, binary.BigEndian, int32(1))
			_ = binary.Write(os.Stdout, binary.BigEndian, int32(100))
			_, _ = os.Stdout.Write([]byte("short"))
			return
		default:
			write(0, make([]byte, 32))
		}
	}
}

func testClient(t *testing.T, mode string) *Operation {
	t.Helper()
	t.Setenv("KALKAN_JAVA_TEST_WORKER", mode)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	provider := filepath.Join(t.TempDir(), "provider.jar")
	if err := os.WriteFile(provider, []byte("test provider"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New(Config{ProviderPath: provider, Executable: executable, MaxOutputSize: 4096}).WithContext(t.Context())
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
		if c.directory != "" {
			if _, err := os.Stat(c.directory); !os.IsNotExist(err) {
				t.Errorf("worker directory still exists: %v", err)
			}
		}
	})
	return c
}

func TestCanceledOperationTerminatesSession(t *testing.T) {
	c := testClient(t, "hang")
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c = c.WithContext(ctx)
	_, err := c.HashData(ckalkan.SHA256, 0, []byte("payload"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Hash = %v, want deadline", err)
	}
	c = c.WithContext(context.Background())
	if _, err := c.HashData(ckalkan.SHA256, 0, nil); !errors.Is(err, ErrWorkerFailed) {
		t.Fatalf("reuse = %v, want failed worker", err)
	}
	select {
	case <-c.exited:
	case <-time.After(5 * time.Second):
		t.Fatal("worker was not reaped")
	}
}

func TestCanceledContextDoesNotLeakBetweenOperations(t *testing.T) {
	operation := testClient(t, "ok")
	if err := operation.Init(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := operation.WithContext(ctx).HashData(ckalkan.SHA256, 0, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled operation = %v", err)
	}
	// Cancellation before IPC leaves the session and other operations usable.
	if digest, err := operation.HashData(ckalkan.SHA256, 0, nil); err != nil || len(digest) != 32 {
		t.Fatalf("independent operation = %x, %v", digest, err)
	}
}

func TestOperationErrorsPreserveSession(t *testing.T) {
	for _, mode := range []string{"oversized", "crypto-error"} {
		t.Run(mode, func(t *testing.T) {
			c := testClient(t, mode)
			if err := c.Init(); err != nil {
				t.Fatal(err)
			}
			_, err := c.HashData(ckalkan.SHA256, 0, nil)
			if err == nil || errors.Is(err, ErrWorkerFailed) {
				t.Fatalf("operation = %v, want recoverable error", err)
			}
			if mode == "oversized" {
				var limit *ckalkan.OutputBufferLimitError
				if !errors.As(err, &limit) || limit.Requested != 10000 || limit.Limit != 4096 {
					t.Fatalf("limit error = %#v, %v", limit, err)
				}
			}
			if digest, err := c.HashData(ckalkan.SHA256, 0, nil); err != nil || len(digest) != 32 {
				t.Fatalf("recovery = %x, %v", digest, err)
			}
		})
	}
}

func TestUnexpectedExitAndTruncatedResponse(t *testing.T) {
	for _, mode := range []string{"exit-init", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			c := testClient(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c = c.WithContext(ctx)
			err := c.Init()
			if mode == "truncated" {
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.HashData(ckalkan.SHA256, 0, nil)
			}
			if !errors.Is(err, ErrWorkerFailed) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("failure = %v, want immediate worker failure", err)
			}
		})
	}
}

func TestCancellationClosesReaderWithWriterStillOpen(t *testing.T) {
	request, input, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = request.Close(); _ = input.Close() })
	output, retainedWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = output.Close(); _ = retainedWriter.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c := New(Config{MaxOutputSize: 4096}).WithContext(t.Context())
	c = c.WithContext(ctx)
	c.input, c.output, c.reader = input, output, bufio.NewReader(output)
	done := make(chan error, 1)
	go func() {
		_, err := c.HashData(ckalkan.SHA256, 0, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Hash = %v, want deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation waits for a writer retained outside the worker")
	}
}
