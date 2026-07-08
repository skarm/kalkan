package kalkan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/skarm/kalkan/ckalkan"
)

func TestSignZIPUsesOutputPath(t *testing.T) {
	outDir := t.TempDir()
	inputPath := writeTestZIPInput(t, outDir, "payload.txt")
	outputPath := filepath.Join(outDir, "signed-container.zip")
	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			if req.Alias != "signing-key" {
				t.Fatalf("alias = %q, want signing-key", req.Alias)
			}
			if req.FilePath != inputPath {
				t.Fatalf("file path = %q, want %q", req.FilePath, inputPath)
			}
			if req.Name != "signed-container" {
				t.Fatalf("name = %q, want signed-container", req.Name)
			}
			if req.OutDir != outDir {
				t.Fatalf("out dir = %q, want %q", req.OutDir, outDir)
			}
			if req.Flags != ckalkan.NoCheckCertTime {
				t.Fatalf("flags = %#x, want NoCheckCertTime", req.Flags)
			}
			return os.WriteFile(filepath.Join(req.OutDir, req.Name+".zip"), []byte("zip"), 0o644)
		},
	}
	client := &Client{library: native}

	zipFile, err := client.SignZIP(context.Background(), SignZIPRequest{
		Alias:                "signing-key",
		InputPath:            inputPath,
		OutputPath:           outputPath,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("SignZIP returned error: %v", err)
	}
	if zipFile.Path != outputPath {
		t.Fatalf("ZIP path = %q, want %q", zipFile.Path, outputPath)
	}
}

func TestZIPOutputPlanRejectsMissingExtension(t *testing.T) {
	_, err := zipOutputPlan(filepath.Join("/tmp", "signed-container"))
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "ZIP output extension must be .zip") {
		t.Fatalf("zipOutputPlan error = %v, want .zip rejection", err)
	}
}

func TestZIPOutputPlanWithLowercaseExtension(t *testing.T) {
	plan, err := zipOutputPlan(filepath.Join("/tmp", "signed-container.zip"))
	if err != nil {
		t.Fatalf("zipOutputPlan returned error: %v", err)
	}
	if plan.desiredPath != filepath.Join("/tmp", "signed-container.zip") {
		t.Fatalf("desired path = %q, want /tmp/signed-container.zip", plan.desiredPath)
	}
	if plan.nativeName != "signed-container" {
		t.Fatalf("native name = %q, want signed-container without .zip", plan.nativeName)
	}
}

func TestZIPOutputPlanAcceptsCaseInsensitiveZIPExtension(t *testing.T) {
	for _, test := range []struct {
		outputPath string
		wantPath   string
	}{
		{
			outputPath: filepath.Join("/tmp", "signed-container.ZIP"),
			wantPath:   filepath.Join("/tmp", "signed-container.zip"),
		},
		{
			outputPath: filepath.Join("/tmp", "signed-container.Zip"),
			wantPath:   filepath.Join("/tmp", "signed-container.zip"),
		},
	} {
		outputPath := test.outputPath
		t.Run(filepath.Base(outputPath), func(t *testing.T) {
			plan, err := zipOutputPlan(outputPath)
			if err != nil {
				t.Fatalf("zipOutputPlan returned error: %v", err)
			}
			if plan.desiredPath != test.wantPath {
				t.Fatalf("desired path = %q, want normalized path %q", plan.desiredPath, test.wantPath)
			}
			if plan.nativeName != "signed-container" {
				t.Fatalf("native name = %q, want signed-container without .zip", plan.nativeName)
			}
		})
	}
}

func TestZIPOutputPlanRejectsEmptyOutputNames(t *testing.T) {
	tests := []struct {
		name       string
		outputPath string
		want       string
	}{
		{name: "empty path", outputPath: "", want: "ZIP output path is empty"},
		{name: "root path", outputPath: string(filepath.Separator), want: "ZIP output file name is empty"},
		{name: "extension only", outputPath: ".zip", want: "ZIP output file name is empty"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := zipOutputPlan(test.outputPath)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("zipOutputPlan(%q) error = %v, want %q", test.outputPath, err, test.want)
			}
		})
	}
}

func TestSignZIPWithLowercaseExtensionDoesNotAppendExtension(t *testing.T) {
	outDir := t.TempDir()
	inputPath := writeTestZIPInput(t, outDir, "payload.txt")
	outputPath := filepath.Join(outDir, "signed-container.zip")
	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			if req.Name != "signed-container" {
				t.Fatalf("native name = %q, want signed-container without .zip", req.Name)
			}
			return os.WriteFile(filepath.Join(req.OutDir, req.Name+".zip"), []byte("zip"), 0o644)
		},
	}
	client := &Client{library: native}

	zipFile, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  inputPath,
		OutputPath: outputPath,
	})
	if err != nil {
		t.Fatalf("SignZIP returned error: %v", err)
	}
	if zipFile.Path != outputPath {
		t.Fatalf("ZIP path = %q, want %q", zipFile.Path, outputPath)
	}
	if _, err := os.Stat(outputPath + ".zip"); !os.IsNotExist(err) {
		t.Fatalf("unexpected .zip.zip output stat error = %v", err)
	}
}

func TestSignZIPAcceptsCaseInsensitiveZIPExtension(t *testing.T) {
	outDir := t.TempDir()
	inputPath := writeTestZIPInput(t, outDir, "payload.txt")
	outputPath := filepath.Join(outDir, "signed-container.ZIP")
	normalizedOutputPath := filepath.Join(outDir, "signed-container.zip")
	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			if req.Name != "signed-container" {
				t.Fatalf("native name = %q, want signed-container without .zip", req.Name)
			}

			return os.WriteFile(filepath.Join(req.OutDir, req.Name+".zip"), []byte("zip"), 0o644)
		},
	}
	client := &Client{library: native}

	zipFile, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  inputPath,
		OutputPath: outputPath,
	})
	if err != nil {
		t.Fatalf("SignZIP returned error: %v", err)
	}
	if zipFile.Path != normalizedOutputPath {
		t.Fatalf("ZIP path = %q, want normalized path %q", zipFile.Path, normalizedOutputPath)
	}
}

func TestSignZIPRejectsMissingPathsBeforeNativeCall(t *testing.T) {
	outDir := t.TempDir()
	inputPath := writeTestZIPInput(t, outDir, "payload.txt")

	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			t.Fatal("SignZIP called native ZipConSign for missing required path")
			return nil
		},
	}
	client := &Client{library: native}

	tests := []struct {
		name string
		req  SignZIPRequest
		want string
	}{
		{
			name: "missing input path",
			req:  SignZIPRequest{OutputPath: filepath.Join(outDir, "signed.zip")},
			want: "ZIP input file path is empty",
		},
		{
			name: "missing output path",
			req:  SignZIPRequest{InputPath: inputPath},
			want: "ZIP output path is empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.SignZIP(context.Background(), test.req)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("SignZIP error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSignZIPAcceptsNativeCreatedDesiredOutputPath(t *testing.T) {
	outDir := t.TempDir()
	inputPath := writeTestZIPInput(t, outDir, "payload.txt")
	outputPath := filepath.Join(outDir, "signed-container.zip")
	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			return os.WriteFile(outputPath, []byte("zip"), 0o644)
		},
	}
	client := &Client{library: native}

	zipFile, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  inputPath,
		OutputPath: outputPath,
	})
	if err != nil {
		t.Fatalf("SignZIP returned error: %v", err)
	}
	if zipFile.Path != outputPath {
		t.Fatalf("ZIP path = %q, want %q", zipFile.Path, outputPath)
	}
}

func TestSignZIPRejectsMissingExtensionBeforeNativeCall(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "signed-container")
	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			t.Fatal("SignZIP called native ZipConSign for output without .zip extension")
			return nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  "/tmp/payload.txt",
		OutputPath: outputPath,
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "ZIP output extension must be .zip") {
		t.Fatalf("SignZIP error = %v, want .zip rejection", err)
	}
}

func TestSignZIPRejectsMissingNativeOutput(t *testing.T) {
	outDir := t.TempDir()
	inputPath := writeTestZIPInput(t, outDir, "payload.txt")
	outputPath := filepath.Join(outDir, "signed.zip")
	client := &Client{library: &fakeNative{zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
		return nil
	}}}

	_, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  inputPath,
		OutputPath: outputPath,
	})
	if err == nil || !strings.Contains(err.Error(), "ZIP output was not created") {
		t.Fatalf("SignZIP error = %v, want missing native output rejection", err)
	}
}

func TestSignZIPRejectsNativeCreatedNonRegularOutput(t *testing.T) {
	outDir := t.TempDir()
	if err := os.Chmod(outDir, 0o700); err != nil {
		t.Fatalf("chmod output dir: %v", err)
	}
	inputPath := writeTestZIPInput(t, outDir, "payload.txt")
	outputPath := filepath.Join(outDir, "signed.zip")
	client := &Client{library: &fakeNative{zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
		return os.Mkdir(outputPath, 0o700)
	}}}

	_, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  inputPath,
		OutputPath: outputPath,
	})
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("SignZIP error = %v, want non-regular native output rejection", err)
	}
	if _, statErr := os.Lstat(outputPath); !os.IsNotExist(statErr) {
		t.Fatalf("non-regular output stat error = %v, want cleaned up output", statErr)
	}
}

func TestSignZIPRejectsPreExistingOutputPathBeforeNativeCall(t *testing.T) {
	outDir := t.TempDir()
	outputPath := filepath.Join(outDir, "signed-container.zip")
	if err := os.WriteFile(outputPath, []byte("old zip"), 0o600); err != nil {
		t.Fatal(err)
	}

	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			t.Fatal("SignZIP called native ZipConSign for an existing output path")
			return nil
		},
	}
	client := &Client{library: native}

	_, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  "/tmp/payload.txt",
		OutputPath: outputPath,
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("SignZIP error = %v, want pre-existing output error", err)
	}
}

func TestSignZIPRepeatsOutputCheckInsideNativeGate(t *testing.T) {
	dir := t.TempDir()
	inputPath := writeTestZIPInput(t, dir, "payload.txt")
	outputPath := filepath.Join(dir, "signed.zip")
	createdPath := outputPath

	firstEnteredNative := make(chan struct{})
	releaseFirstNative := make(chan struct{})
	secondWaitingForGate := make(chan struct{})
	var nativeCalls atomic.Int32

	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			switch nativeCalls.Add(1) {
			case 1:
				close(firstEnteredNative)
				<-releaseFirstNative
				return os.WriteFile(createdPath, []byte("first zip"), 0o600)
			default:
				return errors.New("native overwrite call should have been blocked by inner output check")
			}
		},
	}
	client := &Client{library: native}

	firstDone := make(chan error, 1)
	go func() {
		_, err := client.SignZIP(context.Background(), SignZIPRequest{
			InputPath:  inputPath,
			OutputPath: outputPath,
		})
		firstDone <- err
	}()

	<-firstEnteredNative

	secondCtx := &gateWaitContext{
		Context: context.Background(),
		done:    make(chan struct{}),
		waiting: secondWaitingForGate,
	}
	secondDone := make(chan error, 1)
	go func() {
		_, err := client.SignZIP(secondCtx, SignZIPRequest{
			InputPath:  inputPath,
			OutputPath: outputPath,
		})
		secondDone <- err
	}()

	<-secondWaitingForGate
	close(releaseFirstNative)

	if err := <-firstDone; err != nil {
		t.Fatalf("first SignZIP returned error: %v", err)
	}
	err := <-secondDone
	if err == nil || !strings.Contains(err.Error(), "ZIP output already exists") {
		t.Fatalf("second SignZIP error = %v, want ZIP output already exists", err)
	}
	if got := nativeCalls.Load(); got != 1 {
		t.Fatalf("native ZipConSign calls = %d, want 1", got)
	}

	data, err := os.ReadFile(createdPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first zip" {
		t.Fatalf("created ZIP data = %q, want first zip", data)
	}
}

func TestVerifyZIPCanReturnSignerCertificate(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "signed.zip")
	if err := os.WriteFile(sourcePath, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}

	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			if zipFile != sourcePath {
				t.Fatalf("zip path = %q, want source path %q", zipFile, sourcePath)
			}
			if flags != ckalkan.NoCheckCertTime {
				t.Fatalf("flags = %#x, want NoCheckCertTime", flags)
			}
			return "Checking zip - OK", nil
		},
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			if zipFile != sourcePath {
				t.Fatalf("cert zip path = %q, want source path %q", zipFile, sourcePath)
			}
			if flags != ckalkan.NoCheckCertTime {
				t.Fatalf("cert flags = %#x, want NoCheckCertTime", flags)
			}
			if signID != 2 {
				t.Fatalf("signer id = %d, want 2", signID)
			}
			return []byte("zip-cert"), nil
		},
	}
	client := &Client{library: native}

	verification, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{
		Path:                    sourcePath,
		SignerID:                2,
		ReturnSignerCertificate: true,
		CertificateTimeCheck:    SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("VerifyZIP returned error: %v", err)
	}
	if !verification.Valid {
		t.Fatal("verification should be valid when native verification returns no error")
	}
	if verification.Info != "Checking zip - OK" {
		t.Fatalf("ZIP info = %q", verification.Info)
	}
	if string(verification.SignerCert) != "zip-cert" {
		t.Fatalf("ZIP signer cert = %q, want zip-cert", verification.SignerCert)
	}
}

func TestVerifyZIPRejectsEmptySignerCertificate(t *testing.T) {
	sourcePath := writeTestZIPInput(t, t.TempDir(), "signed.zip")
	client := &Client{library: &fakeNative{
		zipConVerifyFunc: func(string, ckalkan.Flag) (string, error) {
			return "Checking zip - OK", nil
		},
		getCertFromZipFileFunc: func(string, ckalkan.Flag, int) ([]byte, error) {
			return []byte("\x00"), nil
		},
	}}

	_, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{
		Path:                    sourcePath,
		ReturnSignerCertificate: true,
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "ZIP signer certificate output is empty") {
		t.Fatalf("VerifyZIP error = %v, want empty signer certificate rejection", err)
	}
}

func TestVerifyZIPReturnsNativeSignerCertificateWithoutExtraClone(t *testing.T) {
	sourcePath := writeTestZIPInput(t, t.TempDir(), "signed.zip")
	nativeCert := []byte("zip-cert")
	client := &Client{library: &fakeNative{
		zipConVerifyFunc: func(string, ckalkan.Flag) (string, error) {
			return "Checking zip - OK", nil
		},
		getCertFromZipFileFunc: func(string, ckalkan.Flag, int) ([]byte, error) {
			return nativeCert, nil
		},
	}}

	verification, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{
		Path:                    sourcePath,
		ReturnSignerCertificate: true,
	})
	if err != nil {
		t.Fatalf("VerifyZIP returned error: %v", err)
	}
	if !sameByteSliceBacking(verification.SignerCert, nativeCert) {
		t.Fatal("VerifyZIP cloned native signer certificate output")
	}
}

func TestZIPSignerCertificateRejectsEmptyNativeCertificate(t *testing.T) {
	sourcePath := writeTestZIPInput(t, t.TempDir(), "signed.zip")
	client := &Client{library: &fakeNative{
		getCertFromZipFileFunc: func(string, ckalkan.Flag, int) ([]byte, error) {
			return nil, nil
		},
	}}

	_, err := client.ZIPSignerCertificate(context.Background(), ZIPSignerCertificateRequest{Path: sourcePath})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "ZIP signer certificate output is empty") {
		t.Fatalf("ZIPSignerCertificate error = %v, want empty signer certificate rejection", err)
	}
}

func TestVerifyZIPWithoutSignerCertificatePassesPathToNativeWithoutRegularFilePreflight(t *testing.T) {
	sourcePath := t.TempDir()
	var called bool
	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			called = true
			if zipFile != sourcePath {
				t.Fatalf("zip path = %q, want %q", zipFile, sourcePath)
			}
			return "Checking zip - OK", nil
		},
	}
	client := &Client{library: native}

	if _, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{Path: sourcePath}); err != nil {
		t.Fatalf("VerifyZIP returned error: %v", err)
	}
	if !called {
		t.Fatal("VerifyZIP did not call native")
	}
}

func TestZIPSignerCertificatePassesPathToNativeWithoutRegularFilePreflight(t *testing.T) {
	sourcePath := t.TempDir()
	var called bool
	native := &fakeNative{
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			called = true
			if zipFile != sourcePath {
				t.Fatalf("zip path = %q, want %q", zipFile, sourcePath)
			}
			return []byte("zip-cert"), nil
		},
	}
	client := &Client{library: native}

	if _, err := client.ZIPSignerCertificate(context.Background(), ZIPSignerCertificateRequest{Path: sourcePath}); err != nil {
		t.Fatalf("ZIPSignerCertificate returned error: %v", err)
	}
	if !called {
		t.Fatal("ZIPSignerCertificate did not call native")
	}
}

func TestZIPMethodsRejectMissingPathBeforeNativeCall(t *testing.T) {
	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			t.Fatal("VerifyZIP called native ZipConVerify without a ZIP path")
			return "", nil
		},
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			t.Fatal("ZIPSignerCertificate called native GetCertFromZipFile without a ZIP path")
			return nil, nil
		},
	}
	client := &Client{library: native}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "VerifyZIP",
			call: func() error {
				_, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{})
				return err
			},
		},
		{
			name: "ZIPSignerCertificate",
			call: func() error {
				_, err := client.ZIPSignerCertificate(context.Background(), ZIPSignerCertificateRequest{})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if err == nil || !strings.Contains(err.Error(), "ZIP path is empty") {
				t.Fatalf("%s error = %v, want empty ZIP path rejection", test.name, err)
			}
		})
	}
}

func TestSignZIPPassesInputPathToNativeWithoutRegularFilePreflight(t *testing.T) {
	inputPath := t.TempDir()
	outputPath := filepath.Join(t.TempDir(), "signed.zip")
	var called bool
	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			called = true
			if req.FilePath != inputPath {
				t.Fatalf("input path = %q, want %q", req.FilePath, inputPath)
			}
			return os.WriteFile(outputPath, []byte("zip"), 0o600)
		},
	}
	client := &Client{library: native}

	if _, err := client.SignZIP(context.Background(), SignZIPRequest{
		InputPath:  inputPath,
		OutputPath: outputPath,
	}); err != nil {
		t.Fatalf("SignZIP returned error: %v", err)
	}
	if !called {
		t.Fatal("SignZIP did not call native")
	}
}

func TestZIPPathMethodsAllowRegularFiles(t *testing.T) {
	dir := t.TempDir()
	sourcePath := writeTestZIPInput(t, dir, "signed.zip")
	outputPath := filepath.Join(dir, "out.zip")

	t.Run("VerifyZIP without signer certificate", func(t *testing.T) {
		var called bool
		native := &fakeNative{
			zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
				called = true
				if zipFile != sourcePath {
					t.Fatalf("zip path = %q, want %q", zipFile, sourcePath)
				}
				return "Checking zip - OK", nil
			},
		}
		client := &Client{library: native}

		_, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{Path: sourcePath})
		if err != nil {
			t.Fatalf("VerifyZIP returned error: %v", err)
		}
		if !called {
			t.Fatal("VerifyZIP did not call native for regular ZIP")
		}
	})

	t.Run("ZIPSignerCertificate", func(t *testing.T) {
		var called bool
		native := &fakeNative{
			getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
				called = true
				if zipFile != sourcePath {
					t.Fatalf("zip path = %q, want %q", zipFile, sourcePath)
				}
				return []byte("zip-cert"), nil
			},
		}
		client := &Client{library: native}

		_, err := client.ZIPSignerCertificate(context.Background(), ZIPSignerCertificateRequest{Path: sourcePath})
		if err != nil {
			t.Fatalf("ZIPSignerCertificate returned error: %v", err)
		}
		if !called {
			t.Fatal("ZIPSignerCertificate did not call native for regular ZIP")
		}
	})

	t.Run("SignZIP input", func(t *testing.T) {
		var called bool
		native := &fakeNative{
			zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
				called = true
				if req.FilePath != sourcePath {
					t.Fatalf("input path = %q, want %q", req.FilePath, sourcePath)
				}
				return os.WriteFile(outputPath, []byte("zip"), 0o600)
			},
		}
		client := &Client{library: native}

		_, err := client.SignZIP(context.Background(), SignZIPRequest{
			InputPath:  sourcePath,
			OutputPath: outputPath,
		})
		if err != nil {
			t.Fatalf("SignZIP returned error: %v", err)
		}
		if !called {
			t.Fatal("SignZIP did not call native for regular input")
		}
	})
}

func TestZIPMethodsCanceledBeforeValidationDoNotCallNative(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	native := &fakeNative{
		zipConSignFunc: func(req ckalkan.ZipConSignRequest) error {
			t.Fatal("SignZIP called native after context cancellation")
			return nil
		},
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			t.Fatal("VerifyZIP called native after context cancellation")
			return "", nil
		},
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			t.Fatal("ZIPSignerCertificate called native after context cancellation")
			return nil, nil
		},
	}
	client := &Client{library: native}

	if _, err := client.SignZIP(ctx, SignZIPRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("SignZIP error = %v, want context.Canceled", err)
	}
	if _, err := client.VerifyZIP(ctx, VerifyZIPRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("VerifyZIP error = %v, want context.Canceled", err)
	}
	if _, err := client.ZIPSignerCertificate(ctx, ZIPSignerCertificateRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ZIPSignerCertificate error = %v, want context.Canceled", err)
	}
}

func TestVerifyZIPReadsSignerCertificateFromSameSourcePath(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "signed.zip")
	if err := os.WriteFile(sourcePath, []byte("original zip"), 0o600); err != nil {
		t.Fatal(err)
	}

	var verifyPath string
	var certPath string
	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			verifyPath = zipFile
			if err := os.WriteFile(sourcePath, []byte("changed zip"), 0o600); err != nil {
				t.Fatal(err)
			}
			return "Checking zip - OK", nil
		},
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			certPath = zipFile
			data, err := os.ReadFile(zipFile)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "changed zip" {
				t.Fatalf("GetCertFromZipFile read %q, want current source path contents", data)
			}
			return []byte("zip-cert"), nil
		},
	}
	client := &Client{library: native}

	verification, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{
		Path:                    sourcePath,
		ReturnSignerCertificate: true,
	})
	if err != nil {
		t.Fatalf("VerifyZIP returned error: %v", err)
	}
	if string(verification.SignerCert) != "zip-cert" {
		t.Fatalf("signer cert = %q, want zip-cert", verification.SignerCert)
	}
	if verifyPath != sourcePath || certPath != sourcePath {
		t.Fatalf("verify path = %q, cert path = %q, want source path %q", verifyPath, certPath, sourcePath)
	}
}

func TestVerifyZIPWithSignerCertificateHonorsCanceledContextBeforeNativeCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			t.Fatal("VerifyZIP called native ZipConVerify after cancellation")
			return "", nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyZIP(ctx, VerifyZIPRequest{
		Path:                    filepath.Join(t.TempDir(), "missing.zip"),
		ReturnSignerCertificate: true,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("VerifyZIP error = %v, want context.Canceled", err)
	}
}

func TestVerifyZIPWithSignerCertificateUsesSourcePathOnNativeFailure(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "signed.zip")
	if err := os.WriteFile(sourcePath, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}

	nativeErr := errors.New("native verify failed")
	var verifyPath string
	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			verifyPath = zipFile
			return "", nativeErr
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{
		Path:                    sourcePath,
		ReturnSignerCertificate: true,
	})
	if !errors.Is(err, nativeErr) {
		t.Fatalf("VerifyZIP error = %v, want native error", err)
	}
	if verifyPath != sourcePath {
		t.Fatalf("verify path = %q, want source path %q", verifyPath, sourcePath)
	}
}

func TestZIPSignerCertificateMapsRequest(t *testing.T) {
	sourcePath := writeTestZIPInput(t, t.TempDir(), "signed.zip")
	native := &fakeNative{
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			if zipFile != sourcePath {
				t.Fatalf("zip path = %q, want %q", zipFile, sourcePath)
			}
			if flags != ckalkan.NoCheckCertTime {
				t.Fatalf("flags = %#x, want NoCheckCertTime", flags)
			}
			if signID != 1 {
				t.Fatalf("signer id = %d, want 1", signID)
			}
			return []byte("zip-cert"), nil
		},
	}
	client := &Client{library: native}

	cert, err := client.ZIPSignerCertificate(context.Background(), ZIPSignerCertificateRequest{
		Path:                 sourcePath,
		SignerID:             1,
		CertificateTimeCheck: SkipCertificateTimeCheck,
	})
	if err != nil {
		t.Fatalf("ZIPSignerCertificate returned error: %v", err)
	}
	if string(cert) != "zip-cert" {
		t.Fatalf("ZIP cert = %q, want zip-cert", cert)
	}
}

func TestZIPSignerCertificateReturnsNativeOutputWithoutExtraClone(t *testing.T) {
	sourcePath := writeTestZIPInput(t, t.TempDir(), "signed.zip")
	nativeCert := []byte("zip-cert")
	client := &Client{library: &fakeNative{
		getCertFromZipFileFunc: func(string, ckalkan.Flag, int) ([]byte, error) {
			return nativeCert, nil
		},
	}}

	cert, err := client.ZIPSignerCertificate(context.Background(), ZIPSignerCertificateRequest{
		Path: sourcePath,
	})
	if err != nil {
		t.Fatalf("ZIPSignerCertificate returned error: %v", err)
	}
	if !sameByteSliceBacking(cert, nativeCert) {
		t.Fatal("ZIPSignerCertificate cloned native certificate output")
	}
}

func TestVerifyZIPRejectsNegativeSignerIDBeforeNativeCall(t *testing.T) {
	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			t.Fatal("VerifyZIP called native ZipConVerify for negative SignerID")
			return "", nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{
		Path:                    "/tmp/signed.zip",
		SignerID:                -1,
		ReturnSignerCertificate: true,
	})
	if err == nil || !strings.Contains(err.Error(), "SignerID") {
		t.Fatalf("VerifyZIP error = %v, want SignerID validation error", err)
	}
}

func TestVerifyZIPRejectsOverflowingSignerIDBeforeNativeCall(t *testing.T) {
	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			t.Fatal("VerifyZIP called native ZipConVerify for overflowing SignerID")
			return "", nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{
		Path:                    "/tmp/signed.zip",
		SignerID:                signerIDOverflowValue(t),
		ReturnSignerCertificate: true,
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "SignerID") {
		t.Fatalf("VerifyZIP error = %v, want ErrInvalidInput SignerID overflow validation error", err)
	}
}

func TestVerifyZIPAllowsMaxSignerID(t *testing.T) {
	sourcePath := writeTestZIPInput(t, t.TempDir(), "signed.zip")
	native := &fakeNative{
		zipConVerifyFunc: func(zipFile string, flags ckalkan.Flag) (string, error) {
			return "Checking zip - OK", nil
		},
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			if signID != maxSignerID {
				t.Fatalf("signer id = %d, want max SignerID %d", signID, maxSignerID)
			}

			return []byte("zip-cert"), nil
		},
	}
	client := &Client{library: native}

	_, err := client.VerifyZIP(context.Background(), VerifyZIPRequest{
		Path:                    sourcePath,
		SignerID:                maxSignerID,
		ReturnSignerCertificate: true,
	})
	if err != nil {
		t.Fatalf("VerifyZIP returned error: %v", err)
	}
}

func TestZIPSignerCertificateRejectsNegativeSignerIDBeforeNativeCall(t *testing.T) {
	native := &fakeNative{
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			t.Fatal("ZIPSignerCertificate called native GetCertFromZipFile for negative SignerID")
			return nil, nil
		},
	}
	client := &Client{library: native}

	_, err := client.ZIPSignerCertificate(context.Background(), ZIPSignerCertificateRequest{
		Path:     "/tmp/signed.zip",
		SignerID: -1,
	})
	if err == nil || !strings.Contains(err.Error(), "SignerID") {
		t.Fatalf("ZIPSignerCertificate error = %v, want SignerID validation error", err)
	}
}

func TestZIPSignerCertificateRejectsOverflowingSignerIDBeforeNativeCall(t *testing.T) {
	native := &fakeNative{
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			t.Fatal("ZIPSignerCertificate called native GetCertFromZipFile for overflowing SignerID")
			return nil, nil
		},
	}
	client := &Client{library: native}

	_, err := client.ZIPSignerCertificate(context.Background(), ZIPSignerCertificateRequest{
		Path:     "/tmp/signed.zip",
		SignerID: signerIDOverflowValue(t),
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "SignerID") {
		t.Fatalf("ZIPSignerCertificate error = %v, want ErrInvalidInput SignerID overflow validation error", err)
	}
}

func TestZIPSignerCertificateAllowsMaxSignerID(t *testing.T) {
	sourcePath := writeTestZIPInput(t, t.TempDir(), "signed.zip")
	native := &fakeNative{
		getCertFromZipFileFunc: func(zipFile string, flags ckalkan.Flag, signID int) ([]byte, error) {
			if signID != maxSignerID {
				t.Fatalf("signer id = %d, want max SignerID %d", signID, maxSignerID)
			}

			return []byte("zip-cert"), nil
		},
	}
	client := &Client{library: native}

	_, err := client.ZIPSignerCertificate(context.Background(), ZIPSignerCertificateRequest{
		Path:     sourcePath,
		SignerID: maxSignerID,
	})
	if err != nil {
		t.Fatalf("ZIPSignerCertificate returned error: %v", err)
	}
}

func writeTestZIPInput(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("zip input"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
