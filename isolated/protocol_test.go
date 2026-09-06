package isolated

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"testing/iotest"

	"github.com/skarm/kalkan"
)

func roundTripPayload(t *testing.T, value wirePayload) wirePayload {
	t.Helper()
	var stream bytes.Buffer
	if err := writeMessage(&stream, message{ID: 1, Payload: value}); err != nil {
		t.Fatal(err)
	}
	result, err := readMessage(&stream)
	if err != nil {
		t.Fatal(err)
	}
	return result.Payload
}

func TestProtocolConsecutiveFrames(t *testing.T) {
	want := message{ID: ^uint64(0), Operation: "Hash", Payload: wirePayload{
		metadata: []byte{1, 0, 2},
		blocks:   []binaryBlock{{data: []byte{0, 128, 255}}, {data: []byte{}}},
	}}
	var stream bytes.Buffer
	for range 2 {
		if err := writeMessage(&stream, want); err != nil {
			t.Fatalf("write consecutive frame: %v", err)
		}
	}
	for range 2 {
		got, err := readMessage(&stream)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("read = %+v, %v; want %+v", got, err, want)
		}
	}
	if _, err := readMessage(&stream); !errors.Is(err, io.EOF) {
		t.Fatalf("end of stream = %v", err)
	}
}

func TestBinaryPayloadIsWrittenWithoutBase64Expansion(t *testing.T) {
	data := bytes.Repeat([]byte{0, 0xff, 0x80, '\n'}, 256<<10)
	request, err := encodeRequest("Hash", kalkan.HashRequest{Data: kalkan.Bytes(data)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	if err := writeMessage(&stream, message{Payload: request}); err != nil {
		t.Fatal(err)
	}
	if stream.Len() > len(data)+4096 || !bytes.HasSuffix(stream.Bytes(), data) {
		t.Fatalf("%d input bytes became a %d-byte frame without the original raw suffix", len(data), stream.Len())
	}
	decoded, err := readMessage(&stream)
	if err != nil || len(decoded.Payload.blocks) != 1 || !bytes.Equal(decoded.Payload.blocks[0].data, data) {
		t.Fatalf("binary payload changed: %v", err)
	}
}

func TestProtocolObservationsUseMetadataSizeLimit(t *testing.T) {
	observations := make([]kalkan.OperationObservation, 256)
	for i := range observations {
		observations[i] = kalkan.OperationObservation{Operation: "LoadTrustedCertificate", ErrorClass: "none"}
	}
	want := message{Operation: "Open", Payload: nullPayload(), Observations: observations}
	var stream bytes.Buffer
	if err := writeMessage(&stream, want); err != nil {
		t.Fatal(err)
	}
	if got, err := readMessage(&stream); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("observations round trip: error = %v, count = %d", err, len(got.Observations))
	}
	want.Observations = make([]kalkan.OperationObservation, 2048)
	if err := writeMessage(&stream, want); !errors.Is(err, errMetadataTooLarge) || stream.Len() != 0 {
		t.Fatalf("oversized metadata: error = %v, written = %d", err, stream.Len())
	}
}

func TestExplicitInputLimitIsCheckedBeforeEncoding(t *testing.T) {
	data := make([]byte, 32<<20)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := encodeRequest("Hash", kalkan.HashRequest{Data: kalkan.Bytes(data)}, 4096)
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(data)
	if !errors.Is(err, kalkan.ErrInvalidInput) {
		t.Fatalf("oversized input = %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 128<<10 {
		t.Fatalf("rejecting 32 MiB allocated %d bytes; input must not be copied or encoded", allocated)
	}
}

func TestProtocolHasFixedBinaryLayout(t *testing.T) {
	// Lengths, ID, operation, empty payload, absent error/observations, no blocks.
	golden, err := hex.DecodeString("000000000000002600000022000000000000000100000005436c6f73650000000000000005000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	want := message{ID: 1, Operation: "Close"}
	var output bytes.Buffer
	if err := writeMessage(&output, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), golden) {
		t.Fatalf("binary layout = %x, want %x", output.Bytes(), golden)
	}
	got, err := readMessage(bytes.NewReader(golden))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("decode golden frame = %+v, %v", got, err)
	}
}

func TestProtocolRejectsInvalidFrames(t *testing.T) {
	var stream bytes.Buffer
	if err := writeMessage(&stream, message{ID: 1, Operation: "Close"}); err != nil {
		t.Fatal(err)
	}
	frame := stream.Bytes()
	for length := 1; length < len(frame); length++ {
		if _, err := readMessage(bytes.NewReader(frame[:length])); !errors.Is(err, ErrProtocol) {
			t.Fatalf("truncated at %d: %v", length, err)
		}
	}
	for _, frame := range [][]byte{
		{0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 8},
		testFrame(nil, 0), testFrame([]byte{255}, 0),
		testBlockLengths(0), testBlockLengths(5), testBlockLengths(^uint64(0)),
	} {
		if _, err := readMessage(bytes.NewReader(frame)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("frame %x: error = %v, want protocol error", frame, err)
		}
	}
}

// The body declares three bytes, while its table declares length bytes.
// No block bytes follow, so even a matching table is truncated.
func testBlockLengths(length uint64) []byte {
	h := metadataWriter{}
	h.uint64(1)
	h.text("Hash")
	h.raw(nil)
	h.raw([]byte{0, 0, 0, 0, 0})
	h.uint32(1)
	h.uint64(length)
	return testFrame(h.data, 3)
}

func TestTruncatedLargeBlocksDoNotAllocateTheirDeclaredSize(t *testing.T) {
	for _, length := range []uint64{129 << 20, 1<<32 + 1, uint64(math.MaxInt) - 1024} {
		if length > uint64(math.MaxInt) {
			continue
		}
		h := metadataWriter{}
		h.uint64(1)
		h.text("Hash")
		h.raw(nil)
		h.raw([]byte{0, 0, 0, 0, 0})
		h.uint32(1)
		h.uint64(length)
		frame := testFrame(h.data, length)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := readMessage(bytes.NewReader(frame))
		runtime.ReadMemStats(&after)
		if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, ErrProtocol) {
			t.Fatalf("truncated %d-byte block = %v", length, err)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 128<<10 {
			t.Fatalf("truncated %d-byte block allocated %d bytes", length, allocated)
		}
	}
}

func TestReadBlockPreservesBytesAndNextBlock(t *testing.T) {
	for _, size := range []int{0, 1, 32 << 10, 32<<10 + 1, 96 << 10, 2<<20 + 17} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			want := make([]byte, size)
			for i := range want {
				want[i] = byte(i)
			}
			stream := bytes.NewReader(append(bytes.Clone(want), 'n'))
			got, err := readBlock(iotest.HalfReader(stream), uint64(size))
			if err != nil || !bytes.Equal(got, want) || got == nil {
				t.Fatalf("readBlock(%d): length=%d, err=%v", size, len(got), err)
			}
			if next, err := stream.ReadByte(); err != nil || next != 'n' {
				t.Fatalf("next block: byte=%q, err=%v", next, err)
			}
		})
	}
}

func TestReadBlockReportsPartialChunks(t *testing.T) {
	for _, size := range []int{0, 1, 32 << 10, 32<<10 + 1, 96 << 10} {
		_, err := readBlock(bytes.NewReader(make([]byte, size)), uint64(size+1))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated after %d bytes: %v", size, err)
		}
	}
	want := errors.New("read failure")
	if _, err := readBlock(iotest.ErrReader(want), 1); !errors.Is(err, want) {
		t.Fatalf("reader error = %v, want %v", err, want)
	}
}

func TestFrameLengthsExceed32Bits(t *testing.T) {
	// Reusing one input block keeps this test small while sending over 4 GiB
	// to a writer that counts bytes without retaining the body.
	data := make([]byte, 8<<20)
	payload := wirePayload{blocks: make([]binaryBlock, 513)}
	for i := range payload.blocks {
		payload.blocks[i].data = data
	}
	writer := &frameCountingWriter{}
	if err := writeMessage(writer, message{Operation: "Hash", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if writer.size <= math.MaxUint32 || binary.BigEndian.Uint64(writer.prefix[:8]) != writer.size-8 {
		t.Fatalf("frame size = %d, prefix = %x", writer.size, writer.prefix)
	}
}

type frameCountingWriter struct {
	size   uint64
	prefix [12]byte
}

func (w *frameCountingWriter) Write(data []byte) (int, error) {
	if w.size == 0 {
		copy(w.prefix[:], data)
	}
	w.size += uint64(len(data))
	return len(data), nil
}

func TestProtocolRejectsOversizedMetadataBeforeWriting(t *testing.T) {
	for _, msg := range []message{
		{Operation: string(make([]byte, maxMetadataSize+1))},
		{Payload: wirePayload{metadata: make([]byte, maxMetadataSize+1)}},
	} {
		var written bytes.Buffer
		if err := writeMessage(&written, msg); !errors.Is(err, errMetadataTooLarge) || written.Len() != 0 {
			t.Fatalf("oversized message: error=%v written=%d", err, written.Len())
		}
	}
}

func TestProtocolHandlesPartialAndFailedWriters(t *testing.T) {
	want := message{Operation: "Close", Payload: nullPayload()}
	partial := &partialWriter{maximum: 2}
	if err := writeMessage(partial, want); err != nil {
		t.Fatal(err)
	}
	if got, err := readMessage(&partial.data); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("partial frame = %+v, %v", got, err)
	}
	if err := writeMessage(&partialWriter{}, want); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress writer = %v", err)
	}
	failure := errors.New("writer failed")
	if err := writeMessage(errorWriter{failure}, want); !errors.Is(err, failure) {
		t.Fatalf("failed writer = %v", err)
	}
}

func testFrame(metadata []byte, bodySize uint64) []byte {
	frame := make([]byte, len(metadata)+12)
	binary.BigEndian.PutUint64(frame[:8], 4+uint64(len(metadata))+bodySize)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(metadata)))
	copy(frame[12:], metadata)
	return frame
}

type partialWriter struct {
	data    bytes.Buffer
	maximum int
}

func (w *partialWriter) Write(data []byte) (int, error) {
	return w.data.Write(data[:min(len(data), w.maximum)])
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func BenchmarkBinaryRequest(b *testing.B) {
	for _, size := range []int{1 << 20, 32 << 20} {
		b.Run(fmt.Sprintf("%dMiB", size>>20), func(b *testing.B) {
			request := kalkan.HashRequest{Data: kalkan.Bytes(make([]byte, size))}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				data, err := encodeRequest("Hash", request, 0)
				if err != nil {
					b.Fatal(err)
				}
				if err := writeMessage(io.Discard, message{Operation: "Hash", Payload: data}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReadBlock(b *testing.B) {
	for _, size := range []int{1024, 16 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			data := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				got, err := readBlock(bytes.NewReader(data), uint64(size))
				if err != nil || len(got) != size {
					b.Fatalf("readBlock: length=%d, err=%v", len(got), err)
				}
			}
		})
	}
}

func FuzzReadMessage(f *testing.F) {
	var frame bytes.Buffer
	if err := writeMessage(&frame, message{ID: 1, Operation: "Close"}); err != nil {
		f.Fatal(err)
	}
	f.Add(frame.Bytes())
	f.Add(testBlockLengths(3))
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readMessage(bytes.NewReader(data))
	})
}
