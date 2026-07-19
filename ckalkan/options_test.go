package ckalkan

import (
	"errors"
	"testing"
)

func TestDefaultConfigHasNoLibrary(t *testing.T) {
	cfg := defaultConfig()
	if cfg.libraryPath != "" {
		t.Fatalf("default library = %q, want empty", cfg.libraryPath)
	}
	if got := outputBufferLimit(cfg.maxBufferSize); got != DefaultMaxOutputBufferSize {
		t.Fatalf("default hard buffer limit = %d, want %d", got, DefaultMaxOutputBufferSize)
	}
}

func TestOptionsOverrideConfig(t *testing.T) {
	cfg := defaultConfig()
	WithLibrary("/opt/kalkan/libkalkancryptwr-64.so")(&cfg)
	WithBufferSize(123)(&cfg)
	WithListBufferSize(456)(&cfg)
	WithMaxBufferSize(789)(&cfg)

	if cfg.libraryPath != "/opt/kalkan/libkalkancryptwr-64.so" {
		t.Fatalf("library path = %q", cfg.libraryPath)
	}
	if cfg.bufferSize != 123 || cfg.listBufferSize != 456 {
		t.Fatalf("unexpected buffer sizes: buffer=%d list=%d", cfg.bufferSize, cfg.listBufferSize)
	}
	if cfg.maxBufferSize != 789 {
		t.Fatalf("hard buffer limit = %d, want 789", cfg.maxBufferSize)
	}
}

func TestWithMaxBufferSizeUsesLastValue(t *testing.T) {
	tests := []struct {
		name string
		size int
		want int
	}{
		{name: "positive", size: 789, want: 789},
		{name: "zero restores default", size: 0},
		{name: "negative remains invalid", size: -1, want: -1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := defaultConfig()
			WithMaxBufferSize(123)(&cfg)
			WithMaxBufferSize(test.size)(&cfg)
			if cfg.maxBufferSize != test.want {
				t.Fatalf("hard buffer limit = %d, want %d", cfg.maxBufferSize, test.want)
			}
		})
	}
}

func TestNewRejectsNegativeMaxBufferSize(t *testing.T) {
	_, err := New(WithMaxBufferSize(-1))
	if !errors.Is(err, ErrInvalidOutputBufferSize) {
		t.Fatalf("New error = %v, want ErrInvalidOutputBufferSize", err)
	}
}

func TestOutputBufferLimitAllowsExplicitLargerLimit(t *testing.T) {
	want := DefaultMaxOutputBufferSize * 2
	if got := outputBufferLimit(want); got != want {
		t.Fatalf("explicit hard buffer limit = %d, want %d", got, want)
	}
}

func TestWithMaxBufferSizeZeroRestoresDefaultLimit(t *testing.T) {
	cfg := defaultConfig()
	WithMaxBufferSize(DefaultMaxOutputBufferSize * 2)(&cfg)
	WithMaxBufferSize(0)(&cfg)

	if got := outputBufferLimit(cfg.maxBufferSize); got != DefaultMaxOutputBufferSize {
		t.Fatalf("hard buffer limit after zero = %d, want default %d", got, DefaultMaxOutputBufferSize)
	}
}

func TestWithLibraryAcceptsAbsolutePath(t *testing.T) {
	cfg := defaultConfig()
	WithLibrary("/opt/kalkan/libkalkancryptwr-64.so")(&cfg)

	if cfg.libraryPath != "/opt/kalkan/libkalkancryptwr-64.so" {
		t.Fatalf("library path = %q, want absolute path", cfg.libraryPath)
	}
}

func TestWithLibraryPreservesPathWhitespace(t *testing.T) {
	cfg := defaultConfig()
	path := " \t/opt/kalkan/libkalkancryptwr-64.so\n"
	WithLibrary(path)(&cfg)

	if cfg.libraryPath != path {
		t.Fatalf("library path = %q, want exact input %q", cfg.libraryPath, path)
	}
}
