package ckalkan

const (
	// Generic and signature outputs use this fallback. Short outputs use smaller
	// operation-specific allocations.
	conservativeOutputBufferSize = 64 << 10

	defaultListBufferSize   = 1 << 20
	defaultOutputBufferSize = conservativeOutputBufferSize

	// defaultSoftOutputBufferSize is an allocation checkpoint, not a limit.
	// Without an explicit hard limit, reported or estimated outputs may grow past
	// it up to the largest size representable by the native C int ABI.
	defaultSoftOutputBufferSize = 64 << 20
	maxNativeOutputBufferSize   = 1<<31 - 1

	initialHashOutputBuffer = 128
	initialInfoOutputBuffer = 4 << 10
	initialCertOutputBuffer = 8 << 10
	initialSignatureBuffer  = conservativeOutputBufferSize
	initialZIPVerifyBuffer  = conservativeOutputBufferSize
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
// setting cannot bound the first native write. Positive values below 64 KiB are
// raised to that conservative minimum.
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

// WithMaxBufferSize sets an opt-in hard cap for every native output allocation.
// Without this option, the default 64 MiB threshold is soft: buffers may grow
// past it when an estimate or the native result requires more space. The native
// C int ABI still imposes an unavoidable maximum of 2^31-1 bytes.
func WithMaxBufferSize(size int) Option {
	return func(c *config) {
		c.maxBufferSize = 0
		if size > 0 {
			c.maxBufferSize = min(size, maxNativeOutputBufferSize)
		}
	}
}

func defaultConfig() config {
	return config{
		listBufferSize: defaultListBufferSize,
	}
}
