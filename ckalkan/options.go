package ckalkan

const (
	// Generic and signature outputs use this fallback. Short outputs use smaller
	// operation-specific allocations.
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

// WithLibrary sets the KalkanCrypt dynamic-library path. On Windows, the path
// must be fully qualified.
func WithLibrary(library string) Option {
	return func(c *config) {
		c.libraryPath = library
	}
}

// WithListBufferSize sets the first allocation size for KC_GetTokens and
// KC_GetCertificatesList. The native ABI does not receive this capacity, so the
// setting cannot bound the first native write.
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
			c.maxBufferSize = max(size, conservativeOutputBufferSize)
		}
	}
}

func defaultConfig() config {
	return config{
		listBufferSize: defaultListBufferSize,
		maxBufferSize:  defaultMaxOutputBufferSize,
	}
}
