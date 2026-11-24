package javakalkan

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

func (c *Operation) exchange(opcode int32, fields [][]byte) ([][]byte, error) {
	if err := c.writeFrame(opcode, fields); err != nil {
		return nil, err
	}

	for requests := 0; ; requests++ {
		status, values, err := c.readFrame()
		if err != nil {
			return nil, err
		}

		if status == 5 {
			if requests >= 128 {
				return nil, errors.New("too many worker network requests")
			}

			body, fetchErr := c.fetch(string(values[0]), string(values[1]), values[2])

			replyStatus := "ok"
			if fetchErr != nil {
				replyStatus = "error"
				// Do not send URLs, response bodies or credentials to diagnostics.
				body = []byte("revocation retrieval failed: " + safeFetchError(fetchErr))
			}

			if err := c.writeFrame(100, [][]byte{[]byte(replyStatus), body}); err != nil {
				return nil, err
			}

			continue
		}

		if status != 0 {
			return nil, &Error{Code: status, Message: string(values[0])}
		}

		return values, nil
	}
}

func (c *Client) writeFrame(opcode int32, fields [][]byte) error {
	if len(fields) > 16 {
		return errors.New("invalid request field count")
	}

	writer := bufio.NewWriter(c.input)

	writeInt := func(v int32) error { return binary.Write(writer, binary.BigEndian, v) }
	if err := writeInt(opcode); err != nil {
		return err
	}

	if err := writeInt(int32(len(fields))); err != nil { //nolint:gosec // Field count is bounded to 16 above.
		return err
	}

	for _, field := range fields {
		if len(field) > math.MaxInt32 {
			return errors.New("request field exceeds Java array limit")
		}

		if err := writeInt(int32(len(field))); err != nil { //nolint:gosec // Field length is bounded to MaxInt32 above.
			return err
		}

		if _, err := writer.Write(field); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func (c *Client) readFrame() (int32, [][]byte, error) {
	readInt := func() (int32, error) { var v int32; err := binary.Read(c.reader, binary.BigEndian, &v); return v, err }

	status, err := readInt()
	if err != nil {
		return 0, nil, fmt.Errorf("read worker response (requires a compatible provider and JDK 17+): %w", err)
	}

	count, err := readInt()
	if err != nil {
		return 0, nil, err
	}

	if status < 0 || status > 5 || count < 0 || count > 3 || (status > 0 && status < 5 && count != 1) || (status == 5 && count != 3) {
		return 0, nil, errors.New("invalid worker response header")
	}

	values := make([][]byte, int(count))
	for i := range values {
		size, err := readInt()
		if err != nil {
			return 0, nil, err
		}

		limit := max(c.cfg.MaxOutputSize, 8192)
		if status != 0 {
			limit = 8192
		}

		if status == 5 && i == 2 {
			limit = 64 * 1024
		}

		if size < 0 || int64(size) > int64(limit) {
			return 0, nil, fmt.Errorf("worker response field exceeds %d bytes", limit)
		}
		// Read incrementally so a truncated frame cannot allocate its declared
		// size before sending any bytes.
		values[i], err = io.ReadAll(io.LimitReader(c.reader, int64(size)))
		if err != nil {
			return 0, nil, err
		}

		if len(values[i]) != int(size) {
			return 0, nil, io.ErrUnexpectedEOF
		}
	}

	return status, values, nil
}
