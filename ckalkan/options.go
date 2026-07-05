package ckalkan

const (
	// Real KalkanCrypt builds can write past very small output buffers in some
	// APIs. The wrapper keeps this conservative size for configured fallbacks and
	// signature-like outputs while allowing smaller operation-specific defaults
	// for short outputs. KC_GetTokens and KC_GetCertificatesList are not
	// length-aware in the SDK header bundled here, so this size is only an
	// allocation policy for those list APIs, not an in-process memory-safety
	// boundary.
	conservativeOutputBufferSize = 64 << 10

	defaultListBufferSize      = 1 << 20
	defaultOutputBufferSize    = conservativeOutputBufferSize
	defaultMaxOutputBufferSize = 64 << 20

	initialHashOutputBuffer = 128
	initialInfoOutputBuffer = 4 << 10
	initialCertOutputBuffer = 8 << 10
	initialSignatureBuffer  = conservativeOutputBufferSize
)

type config struct {
	libraryPath    string
	listBufferSize int
	bufferSize     int
	maxBufferSize  int
}

// Option customizes a Client created by New.
type Option func(*config)

// WithLibrary sets the KalkanCrypt dynamic library path.
func WithLibrary(library string) Option {
	return func(c *config) {
		c.libraryPath = library
	}
}

// WithListBufferSize sets the first allocation size for KC_GetTokens and
// KC_GetCertificatesList. The SDK functions used by this wrapper do not accept
// the allocation capacity, so this option is not a memory-safety boundary. For
// hostile or malformed token stores, isolate these calls in a worker process.
func WithListBufferSize(size int) Option {
	return func(c *config) {
		if size > 0 {
			c.listBufferSize = size
		}
	}
}

// WithBufferSize sets the configured fallback size for native output buffers.
// Values below the conservative output buffer size are raised to that size.
func WithBufferSize(size int) Option {
	return func(c *config) {
		if size > 0 {
			c.bufferSize = size
		}
	}
}

// WithMaxBufferSize sets the hard cap used for initial output buffers and when
// retrying after KCR_BUFFER_TOO_SMALL. Values below the conservative output
// buffer size are raised to that size.
func WithMaxBufferSize(size int) Option {
	return func(c *config) {
		if size > 0 {
			if size < conservativeOutputBufferSize {
				size = conservativeOutputBufferSize
			}

			c.maxBufferSize = size
		}
	}
}

func defaultConfig() config {
	return config{
		listBufferSize: defaultListBufferSize,
		maxBufferSize:  defaultMaxOutputBufferSize,
	}
}
