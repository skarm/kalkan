package ckalkan

const (
	// Generic and signature outputs use this fallback. Short outputs use smaller
	// operation-specific allocations.
	conservativeOutputBufferSize = 64 << 10

	defaultListBufferSize   = 1 << 20
	defaultOutputBufferSize = conservativeOutputBufferSize

	// DefaultMaxOutputBufferSize is the default hard limit for each native output
	// buffer. It is a security and availability boundary, not a promise that any
	// particular operation should consume the full amount. Applications may set
	// a smaller limit with WithMaxBufferSize.
	DefaultMaxOutputBufferSize = 64 << 20
	maxNativeOutputBufferSize  = 1<<31 - 1

	initialRawHash256Capacity  = 32
	initialRawHash512Capacity  = 64
	initialUnknownHashCapacity = 128
	initialEncodedHashCapacity = 256
	initialInfoOutputBuffer    = 4 << 10
	initialCertOutputBuffer    = 8 << 10
	initialSignatureBuffer     = conservativeOutputBufferSize
	initialZIPVerifyBuffer     = conservativeOutputBufferSize
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

// WithMaxBufferSize sets the hard cap for every native output allocation. Zero
// restores DefaultMaxOutputBufferSize. A positive value selects a smaller or
// larger cap and is limited to the native C int maximum of 2^31-1 bytes. A
// negative value makes New return ErrInvalidOutputBufferSize.
func WithMaxBufferSize(size int) Option {
	return func(c *config) {
		if size > 0 {
			c.maxBufferSize = min(size, maxNativeOutputBufferSize)

			return
		}

		c.maxBufferSize = size
	}
}

func defaultConfig() config {
	return config{
		listBufferSize: defaultListBufferSize,
	}
}
