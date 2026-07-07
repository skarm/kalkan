package ckalkan

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewRequiresExplicitLibrary(t *testing.T) {
	if _, err := New(); !errors.Is(err, ErrNoLibrary) {
		t.Fatalf("New without library returned %v, want ErrNoLibrary", err)
	}
}

func TestNewRejectsEmbeddedNULInLibraryBeforeLoader(t *testing.T) {
	if _, err := New(WithLibrary("/tmp/lib.so\x00suffix")); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("New with embedded NUL library returned %v, want NUL rejection", err)
	}
}

func TestNewDoesNotApplyPublicLibraryPathPolicy(t *testing.T) {
	c, err := New(WithLibrary("ckalkan-test-missing-library.so"))
	if err == nil {
		_ = c.Close()
		t.Fatal("New unexpectedly loaded a relative test library")
	}
	if strings.Contains(err.Error(), "absolute library path") {
		t.Fatalf("New error = %v, want loader error without root absolute-path policy", err)
	}
}

func TestFinalizeClearsErrorAndCallsNativeFinalize(t *testing.T) {
	var clearCalls int
	var finalizeCalls int
	ctx := &fakeNativeContext{
		clearErrorFunc: func() {
			clearCalls++
		},
		finalizeFunc: func() {
			finalizeCalls++
		},
	}

	cli := &Client{ctx: ctx, config: defaultConfig()}
	if err := cli.Finalize(); err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}
	if clearCalls != 1 {
		t.Fatalf("ClearError calls = %d, want 1", clearCalls)
	}
	if finalizeCalls != 1 {
		t.Fatalf("Finalize calls = %d, want 1", finalizeCalls)
	}
}

func TestXMLFinalizeClearsErrorAndCallsNativeXMLFinalize(t *testing.T) {
	var clearCalls int
	var finalizeCalls int
	ctx := &fakeNativeContext{
		clearErrorFunc: func() {
			clearCalls++
		},
		xmlFinalizeFunc: func() {
			finalizeCalls++
		},
	}

	cli := &Client{ctx: ctx, config: defaultConfig()}
	if err := cli.XMLFinalize(); err != nil {
		t.Fatalf("XMLFinalize failed: %v", err)
	}
	if clearCalls != 1 {
		t.Fatalf("ClearError calls = %d, want 1", clearCalls)
	}
	if finalizeCalls != 1 {
		t.Fatalf("XMLFinalize calls = %d, want 1", finalizeCalls)
	}
}

func TestClosePoisonsProcessOnNativeCloseError(t *testing.T) {
	closeErr := errors.New("dlclose failed")

	process.mu.Lock()
	previousActive := process.active
	previousPoisoned := process.poisoned
	process.active = true
	process.poisoned = false
	process.mu.Unlock()

	defer func() {
		process.mu.Lock()
		process.active = previousActive
		process.poisoned = previousPoisoned
		process.mu.Unlock()
	}()

	cli := &Client{
		ctx: &fakeNativeContext{
			closeFunc: func() error {
				return closeErr
			},
		},
		config:   defaultConfig(),
		ownsSlot: true,
	}

	err := cli.Close()
	if !errors.Is(err, closeErr) {
		t.Fatalf("Close error = %v, want wrapped close error", err)
	}

	process.mu.Lock()
	active := process.active
	poisoned := process.poisoned
	process.mu.Unlock()

	if !active {
		t.Fatal("process.active was cleared after failed native close")
	}
	if !poisoned {
		t.Fatal("process was not marked poisoned after failed native close")
	}

	_, err = New(WithLibrary(filepath.Join(t.TempDir(), "missing.so")))
	if !errors.Is(err, ErrPoisoned) {
		t.Fatalf("New after failed Close error = %v, want ErrPoisoned", err)
	}
}
