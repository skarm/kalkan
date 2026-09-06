package kalkan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestSignZIPAtomicOutput(t *testing.T) {
	nativeErr := errors.New("native signing failed")
	for _, test := range []struct {
		name            string
		nativeFailure   bool
		competingOutput bool
	}{
		{name: "success"},
		{name: "native failure", nativeFailure: true},
		{name: "competing output", competingOutput: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			outDir := t.TempDir()
			inputPath := writeTestZIPInput(t, outDir, "payload.txt")
			outputPath := filepath.Join(outDir, "signed.zip")
			var stagedDir string
			native := &fakeNative{zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
				stagedDir = req.OutDir
				if stagedDir == outDir || filepath.Dir(stagedDir) != outDir {
					t.Fatalf("staging directory = %q, want private sibling of output", stagedDir)
				}
				info, err := os.Stat(stagedDir)
				if err != nil {
					return err
				}
				if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
					t.Fatalf("staging permissions = %v, want private directory", info.Mode())
				}
				if req.FilePath != inputPath {
					t.Fatalf("native input = %q, want original path %q", req.FilePath, inputPath)
				}
				if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("output exists before publication: %v", err)
				}
				if err := os.WriteFile(filepath.Join(stagedDir, req.Name+".zip"), []byte("signed"), 0o600); err != nil {
					return err
				}
				if test.competingOutput {
					if err := os.WriteFile(outputPath, []byte("competitor"), 0o600); err != nil {
						return err
					}
				}
				if test.nativeFailure {
					return nativeErr
				}
				return nil
			}}
			client, err := openWithLibraryFactory(context.Background(), []Option{
				WithLibraryPath(testLibraryPath()), WithAtomicZIPOutput(),
			}, func(config) (closer, error) { return native, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			result, err := client.SignZIP(context.Background(), SignZIPRequest{InputPath: inputPath, OutputPath: outputPath})
			switch {
			case test.nativeFailure:
				if !errors.Is(err, nativeErr) || result != nil {
					t.Fatalf("result = %v, error = %v", result, err)
				}
				if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed operation published output: %v", err)
				}
			case test.competingOutput:
				if !errors.Is(err, ErrInvalidInput) || result != nil {
					t.Fatalf("result = %v, error = %v", result, err)
				}
				content, readErr := os.ReadFile(outputPath)
				if readErr != nil || string(content) != "competitor" {
					t.Fatalf("competing output = %q, error = %v", content, readErr)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if result.Path != outputPath {
					t.Fatalf("result path = %q", result.Path)
				}
				content, readErr := os.ReadFile(outputPath)
				if readErr != nil || string(content) != "signed" {
					t.Fatalf("output = %q, error = %v", content, readErr)
				}
			}
			if _, err := os.Lstat(stagedDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staging directory remains: %v", err)
			}
		})
	}
}

func TestPublishStagedZIPConcurrentCreate(t *testing.T) {
	dir := t.TempDir()
	plan, err := zipOutputPlan(filepath.Join(dir, "signed.zip"))
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "complete.zip")
	if err := os.WriteFile(staged, []byte("complete ZIP"), 0o600); err != nil {
		t.Fatal(err)
	}
	const publishers = 16
	var successes atomic.Int32
	var group sync.WaitGroup
	start := make(chan struct{})
	for range publishers {
		group.Go(func() {
			<-start
			path, err := publishStagedZIP(staged, plan)
			if err == nil {
				successes.Add(1)
				if path != plan.desiredPath {
					t.Errorf("published path = %q", path)
				}
			} else if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("publication error = %v", err)
			}
		})
	}
	close(start)
	group.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful publications = %d, want 1", got)
	}
	content, err := os.ReadFile(plan.desiredPath)
	if err != nil || string(content) != "complete ZIP" {
		t.Fatalf("published contents = %q, error = %v", content, err)
	}
}
