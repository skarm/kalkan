package isolated

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/skarm/kalkan"
	"github.com/skarm/kalkan/ckalkan"
)

const (
	maxMetadataSize = 64 << 10
	maxBlocks       = 1024
)

var errMetadataTooLarge = errors.New("kalkan isolated: metadata exceeds protocol bounds")

// A frame is: uint64 body size, uint32 header size, binary header, raw blocks.
// Block lengths are uint64 too; raw data has no configurable or default IPC cap.
// Integers use big-endian byte order. The header contains the request ID,
// operation, operation fields, errors, observations and the block length table.
// Parent and child run the same executable; there is no version negotiation.
type message struct {
	ID           uint64
	Operation    string
	Payload      wirePayload
	Error        error
	Observations []kalkan.OperationObservation
}

// Outgoing blocks borrow caller memory until writeMessage completes.
// Received blocks own their storage; metadata never contains their contents.
type wirePayload struct {
	metadata []byte
	blocks   []binaryBlock
}

type binaryBlock struct {
	data []byte
	text string
}

func (b binaryBlock) size() int { return len(b.data) + len(b.text) }

// metadataWriter encodes only bounded, explicitly selected scalar fields.
// It does not traverse Go values or allocate storage for data blocks.
type metadataWriter struct {
	data []byte
	err  error
}

func (e *metadataWriter) reserve(size int) bool {
	if e.err != nil {
		return false
	}

	if size < 0 || size > maxMetadataSize-len(e.data) {
		e.err = errMetadataTooLarge
		return false
	}

	return true
}

func (e *metadataWriter) uint32(value uint32) {
	if e.reserve(4) {
		e.data = binary.BigEndian.AppendUint32(e.data, value)
	}
}

func (e *metadataWriter) uint64(value uint64) {
	if e.reserve(8) {
		e.data = binary.BigEndian.AppendUint64(e.data, value)
	}
}

func (e *metadataWriter) int64(value int64) {
	e.uint64(uint64(value)) //nolint:gosec // Preserve the signed value's bit pattern.
}

func (e *metadataWriter) integer(value int) { e.int64(int64(value)) }

func (e *metadataWriter) boolean(value bool) {
	if e.reserve(1) {
		var bit byte
		if value {
			bit = 1
		}

		e.data = append(e.data, bit)
	}
}

func (e *metadataWriter) rawLength(size int) bool {
	if size < 0 || size > maxMetadataSize {
		e.err = errMetadataTooLarge
		return false
	}

	if !e.reserve(size + 4) {
		return false
	}

	e.uint32(uint32(size))

	return true
}

func (e *metadataWriter) raw(value []byte) {
	if e.rawLength(len(value)) {
		e.data = append(e.data, value...)
	}
}

func (e *metadataWriter) text(value string) {
	if e.rawLength(len(value)) {
		e.data = append(e.data, value...)
	}
}

// A collection count of zero means nil; other values store length + 1.
func (e *metadataWriter) length(length int, present bool) bool {
	if !present {
		e.uint32(0)
		return false
	}

	if length < 0 || length > maxMetadataSize {
		e.err = errMetadataTooLarge
		return false
	}

	e.uint32(uint32(length + 1))

	return e.err == nil
}

type metadataReader struct {
	data []byte
	err  error
}

func (d *metadataReader) take(size int) []byte {
	if d.err != nil {
		return nil
	}

	if size < 0 || size > len(d.data) {
		d.err = fmt.Errorf("%w: truncated metadata", ErrProtocol)
		return nil
	}

	value := d.data[:size]
	d.data = d.data[size:]

	return value
}

func (d *metadataReader) uint32() uint32 {
	value := d.take(4)
	if value == nil {
		return 0
	}

	return binary.BigEndian.Uint32(value)
}

func (d *metadataReader) uint64() uint64 {
	value := d.take(8)
	if value == nil {
		return 0
	}

	return binary.BigEndian.Uint64(value)
}

func (d *metadataReader) int64() int64 {
	return int64(d.uint64()) //nolint:gosec // Restore the signed value's bit pattern.
}

func (d *metadataReader) integer() int {
	value := d.int64()
	if value < math.MinInt || value > math.MaxInt {
		d.err = fmt.Errorf("%w: integer overflow", ErrProtocol)
		return 0
	}

	return int(value)
}

func (d *metadataReader) boolean() bool {
	value := d.take(1)
	if value == nil {
		return false
	}

	if value[0] > 1 {
		d.err = fmt.Errorf("%w: invalid boolean", ErrProtocol)
	}

	return value[0] == 1
}

func (d *metadataReader) raw() []byte {
	size := d.uint32()
	if uint64(size) > uint64(len(d.data)) {
		d.err = fmt.Errorf("%w: invalid metadata length", ErrProtocol)
		return nil
	}

	if size == 0 {
		return nil
	}

	return d.take(int(size))
}

func (d *metadataReader) text() string { return string(d.raw()) }

// Every collection item needs at least minSize bytes in the remaining header.
// Validate the count before allocating its destination slice.
func (d *metadataReader) length(minSize uint32) int {
	encoded := d.uint32()
	if d.err != nil || encoded == 0 {
		return -1
	}

	size := uint64(encoded - 1)
	if minSize == 0 || size > maxMetadataSize || size > uint64(len(d.data))/uint64(minSize) {
		d.err = fmt.Errorf("%w: invalid collection length", ErrProtocol)
		return -1
	}

	return int(size)
}

func (d *metadataReader) finish() error {
	if d.err != nil {
		return d.err
	}

	if len(d.data) != 0 {
		return fmt.Errorf("%w: trailing metadata", ErrProtocol)
	}

	return nil
}

type payloadEncoder struct {
	metadataWriter
	blocks     []binaryBlock
	inputLimit int64
	size       uint64
}

// Block references are one-based; zero means nil. A non-nil empty byte slice
// has its own zero-length block, preserving the distinction from nil.
func (e *payloadEncoder) add(block binaryBlock) uint32 {
	if e.err != nil {
		return 0
	}

	index := len(e.blocks)
	if index >= maxBlocks {
		e.err = errMetadataTooLarge
		return 0
	}

	length := block.size()
	if length < 0 || uint64(length) > math.MaxUint64-e.size {
		e.err = fmt.Errorf("%w: frame size overflow", ErrProtocol)
		return 0
	}

	e.size += uint64(length)

	e.blocks = append(e.blocks, block)

	return uint32(index + 1)
}

func (e *payloadEncoder) bytes(data []byte) {
	var ref uint32

	if data != nil {
		if e.inputLimit > 0 && int64(len(data)) > e.inputLimit {
			e.err = fmt.Errorf("%w: binary input exceeds maximum input size of %d bytes", kalkan.ErrInvalidInput, e.inputLimit)
			return
		}

		ref = e.add(binaryBlock{data: data})
	}

	e.uint32(ref)
}

func (e *payloadEncoder) text(value string) {
	var ref uint32
	if value != "" {
		ref = e.add(binaryBlock{text: value})
	}

	e.uint32(ref)
}

func (e *payloadEncoder) finish() (wirePayload, error) {
	if e.err != nil {
		return wirePayload{}, e.err
	}

	return wirePayload{metadata: e.data, blocks: e.blocks}, nil
}

type payloadDecoder struct {
	metadataReader
	blocks []binaryBlock
}

func decodePayload(payload wirePayload) payloadDecoder {
	return payloadDecoder{metadataReader: metadataReader{data: payload.metadata}, blocks: payload.blocks}
}

func (d *payloadDecoder) bytes() []byte {
	ref := d.uint32()
	if ref == 0 {
		return nil
	}

	if uint64(ref) > uint64(len(d.blocks)) {
		d.err = fmt.Errorf("%w: invalid binary block reference", ErrProtocol)
		return nil
	}

	block := d.blocks[ref-1]
	if block.text != "" {
		return []byte(block.text)
	}

	return block.data
}

func (d *payloadDecoder) text() string { return string(d.bytes()) }
func nullPayload() wirePayload         { return wirePayload{} }
func (p wirePayload) isNull() bool     { return len(p.metadata) == 0 && len(p.blocks) == 0 }

func readMessage(reader io.Reader) (message, error) {
	var prefix [8]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		if err == io.EOF {
			return message{}, err
		}

		return message{}, fmt.Errorf("%w: truncated frame header: %w", ErrProtocol, err)
	}

	size := binary.BigEndian.Uint64(prefix[:])

	if size < 4 {
		return message{}, fmt.Errorf("%w: invalid frame size", ErrProtocol)
	}

	if _, err := io.ReadFull(reader, prefix[:4]); err != nil {
		return message{}, fmt.Errorf("%w: missing metadata size: %w", ErrProtocol, err)
	}

	headerSize := uint64(binary.BigEndian.Uint32(prefix[:4]))
	if headerSize == 0 || headerSize > maxMetadataSize || headerSize > size-4 {
		return message{}, fmt.Errorf("%w: invalid metadata size", ErrProtocol)
	}

	metadata := make([]byte, int(headerSize))
	if _, err := io.ReadFull(reader, metadata); err != nil {
		return message{}, fmt.Errorf("%w: truncated metadata: %w", ErrProtocol, err)
	}

	d := metadataReader{data: metadata}
	result := message{ID: d.uint64(), Operation: d.text()}
	result.Payload.metadata = d.raw()
	tail := d.raw()

	count := d.uint32()
	if count > maxBlocks || uint64(count)*8 > uint64(len(d.data)) {
		return message{}, fmt.Errorf("%w: invalid block count", ErrProtocol)
	}

	lengths := d.take(int(count) * 8)
	if err := d.finish(); err != nil {
		return message{}, err
	}

	remaining := size - 4 - headerSize

	for i := range count {
		length := binary.BigEndian.Uint64(lengths[i*8:])
		if length > uint64(math.MaxInt) || length > remaining {
			return message{}, fmt.Errorf("%w: invalid binary block length", ErrProtocol)
		}

		remaining -= length
	}

	if remaining != 0 {
		return message{}, fmt.Errorf("%w: inconsistent frame size", ErrProtocol)
	}

	if count != 0 {
		result.Payload.blocks = make([]binaryBlock, int(count))
	}

	for i := range result.Payload.blocks {
		length := binary.BigEndian.Uint64(lengths[i*8:])

		data, err := readBlock(reader, length)
		if err != nil {
			return message{}, fmt.Errorf("%w: truncated binary block: %w", ErrProtocol, err)
		}

		result.Payload.blocks[i].data = data
	}

	details := payloadDecoder{metadataReader: metadataReader{data: tail}, blocks: result.Payload.blocks}
	result.Error = details.decodeError(0)

	result.Observations = details.observations()
	if err := details.finish(); err != nil {
		return message{}, err
	}

	return result, nil
}

// Read bounded chunks as bytes arrive, then join them once. This avoids repeated
// copying of the growing prefix, and a truncated frame cannot force allocation
// of its full declared size. The SDK API ultimately requires contiguous bytes.
func readBlock(reader io.Reader, length uint64) ([]byte, error) {
	if length > uint64(math.MaxInt) {
		return nil, fmt.Errorf("%w: block length overflows int", ErrProtocol)
	}

	const maxChunkSize = 1 << 20

	chunkSize := 32 << 10
	remaining := int(length)

	var chunks [][]byte

	for remaining > 0 {
		chunk := make([]byte, min(remaining, chunkSize))
		if _, err := io.ReadFull(reader, chunk); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}

			return nil, err
		}

		remaining -= len(chunk)
		if remaining == 0 && len(chunks) == 0 {
			return chunk, nil
		}

		chunks = append(chunks, chunk)
		chunkSize = min(chunkSize*2, maxChunkSize)
	}

	data := make([]byte, int(length))
	offset := 0

	for _, chunk := range chunks {
		offset += copy(data[offset:], chunk)
	}

	return data, nil
}

func writeMessage(writer io.Writer, msg message) error {
	if len(msg.Payload.metadata) > maxMetadataSize || len(msg.Payload.blocks) > maxBlocks {
		return errMetadataTooLarge
	}

	e := payloadEncoder{}
	for _, block := range msg.Payload.blocks {
		e.add(block)
	}

	e.encodeError(msg.Error, 0)
	e.observations(msg.Observations)

	if e.err != nil {
		return e.err
	}

	header := metadataWriter{}
	header.uint64(msg.ID)
	header.text(msg.Operation)
	header.raw(msg.Payload.metadata)
	header.raw(e.data)

	count := len(e.blocks)
	if count > maxBlocks {
		return errMetadataTooLarge
	}

	header.uint32(uint32(count))

	for _, block := range e.blocks {
		length := block.size()
		if length < 0 {
			return errMetadataTooLarge
		}

		header.uint64(uint64(length))
	}

	if header.err != nil {
		return header.err
	}

	headerSize := uint64(len(header.data))
	if headerSize > maxMetadataSize {
		return errMetadataTooLarge
	}

	if e.size > math.MaxUint64-headerSize-4 {
		return fmt.Errorf("%w: frame size overflow", ErrProtocol)
	}

	size := e.size + headerSize + 4

	var prefix [12]byte
	binary.BigEndian.PutUint64(prefix[:8], size)
	binary.BigEndian.PutUint32(prefix[8:], uint32(headerSize))

	if err := writeAll(writer, prefix[:]); err != nil {
		return err
	}

	if err := writeAll(writer, header.data); err != nil {
		return err
	}

	for _, block := range e.blocks {
		if block.text != "" {
			if err := writeText(writer, block.text); err != nil {
				return err
			}
		} else if err := writeAll(writer, block.data); err != nil {
			return err
		}
	}

	return nil
}

func (e *payloadEncoder) observations(values []kalkan.OperationObservation) {
	if !e.length(len(values), values != nil) {
		return
	}

	for _, value := range values {
		e.metadataWriter.text(value.Operation)
		e.int64(int64(value.QueueWait))
		e.int64(int64(value.NativeDuration))
		e.int64(int64(value.TotalDuration))
		e.metadataWriter.text(value.ErrorClass)
		e.uint64(uint64(value.NativeCode))
		e.boolean(value.Expected)
	}
}

func (d *payloadDecoder) observations() []kalkan.OperationObservation {
	count := d.length(41)
	if count < 0 {
		return nil
	}

	values := make([]kalkan.OperationObservation, count)
	for i := range values {
		values[i] = kalkan.OperationObservation{
			Operation: d.metadataReader.text(), QueueWait: time.Duration(d.int64()),
			NativeDuration: time.Duration(d.int64()), TotalDuration: time.Duration(d.int64()),
			ErrorClass: d.metadataReader.text(), NativeCode: ckalkan.ErrorCode(d.uint64()), Expected: d.boolean(),
		}
	}

	return values
}

func writeText(writer io.Writer, value string) error {
	buffer := make([]byte, min(len(value), 32<<10))
	for len(value) != 0 {
		n := copy(buffer, value)
		if err := writeAll(writer, buffer[:n]); err != nil {
			return err
		}

		value = value[n:]
	}

	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}

		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}

		data = data[n:]
	}

	return nil
}
