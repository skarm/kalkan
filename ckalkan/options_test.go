package ckalkan

import "testing"

func TestDefaultConfigHasNoLibrary(t *testing.T) {
	cfg := defaultConfig()
	if cfg.libraryPath != "" {
		t.Fatalf("default library = %q, want empty", cfg.libraryPath)
	}
	if cfg.maxBufferSize != 0 {
		t.Fatalf("default hard buffer limit = %d, want disabled", cfg.maxBufferSize)
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
		{name: "zero disables", size: 0},
		{name: "negative disables", size: -1},
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
