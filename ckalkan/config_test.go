package ckalkan

import "testing"

func TestDefaultConfigHasNoLibrary(t *testing.T) {
	cfg := defaultConfig()
	if cfg.libraryPath != "" {
		t.Fatalf("default library = %q, want empty", cfg.libraryPath)
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
	if cfg.maxBufferSize != conservativeOutputBufferSize {
		t.Fatalf("max buffer should be clamped to %d, got %d", conservativeOutputBufferSize, cfg.maxBufferSize)
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
