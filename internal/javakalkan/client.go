// Package javakalkan implements the optional subprocess backend for Kalkan's
// Java provider. The proprietary provider JAR is supplied by the caller.
package javakalkan

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/skarm/kalkan/ckalkan"
	"github.com/skarm/kalkan/internal/javakalkan/worker"
)

var (
	ErrUnsupported  = errors.New("kalkan java: unsupported operation")
	ErrInvalidInput = errors.New("kalkan java: invalid input")
	ErrWorkerFailed = errors.New("kalkan java: worker failed")
)

// Error is a Java operation failure, distinct from native SDK error codes.
type Error struct {
	Operation string
	Code      int32
	Message   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("kalkan java: %s: %s", e.Operation, e.Message)
}

func (e *Error) Unwrap() error {
	switch e.Code {
	case 1:
		return ErrInvalidInput
	case 2:
		return ErrUnsupported
	default:
		return nil
	}
}

type Config struct {
	ProviderPath     string
	Executable       string
	XMLLibraries     []string
	MaxInputSize     int64
	MaxOutputSize    int
	RevocationMode   string
	RevocationSource string
	ValidateURL      func(string) (string, error)
}

// Client owns the persistent Java process. Calls and Close are serialized by
// the enclosing public client; request contexts live in separate Operation views.
type Client struct {
	cfg       Config
	cmd       *exec.Cmd
	input     *os.File
	output    *os.File
	reader    *bufio.Reader
	exited    chan struct{}
	directory string
	failed    error
	closed    bool
	proxyURL  *url.URL
}

func New(cfg Config) *Client { return &Client{cfg: cfg} }

// Operation pairs the shared session with a request context. The caller must
// hold the session's call gate during use. Cancellation during IPC terminates
// the session.
type Operation struct {
	*Client
	ctx context.Context
}

// WithContext returns an operation with its own context; nil uses context.Background.
func (c *Client) WithContext(ctx context.Context) *Operation {
	if ctx == nil {
		ctx = context.Background()
	}

	return &Operation{Client: c, ctx: ctx}
}

func (c *Operation) Init() error {
	if c.closed {
		return ErrWorkerFailed
	}

	if c.cmd != nil {
		return errors.New("kalkan java: already initialized")
	}

	if err := c.ctx.Err(); err != nil {
		return err
	}

	info, err := os.Stat(c.cfg.ProviderPath)
	if err != nil {
		return fmt.Errorf("kalkan java: provider JAR: %w", err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: provider JAR must be a regular file", ErrInvalidInput)
	}

	executable := c.cfg.Executable
	if executable == "" {
		executable = "java"
	}

	launcher, err := exec.LookPath(executable)
	if err != nil {
		return fmt.Errorf("kalkan java: find JDK launcher: %w", err)
	}

	c.directory, err = os.MkdirTemp("", "kalkan-java-")
	if err != nil {
		return fmt.Errorf("kalkan java: create worker directory: %w", err)
	}

	classpath := []string{c.cfg.ProviderPath}
	for _, library := range c.cfg.XMLLibraries {
		info, err := os.Stat(library)
		if err != nil {
			return fmt.Errorf("java XML library: %w", err)
		}

		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: java XML library must be a regular file", ErrInvalidInput)
		}

		classpath = append(classpath, library)
	}

	sourcePath, err := worker.Prepare(c.directory, len(c.cfg.XMLLibraries) != 0)
	if err != nil {
		return err
	}

	childInput, input, err := os.Pipe()
	if err != nil {
		return err
	}
	defer childInput.Close()

	output, childOutput, err := os.Pipe()
	if err != nil {
		_ = input.Close()
		return err
	}
	defer childOutput.Close()

	c.input, c.output = input, output
	c.reader = bufio.NewReader(output)
	// Private pipes keep protocol bytes separate from application stdio and
	// prevent exec.Cmd.Wait from closing a reader while a reply is drained.
	c.cmd = exec.Command(launcher, "-cp", strings.Join(classpath, string(os.PathListSeparator)), sourcePath, c.directory, strconv.FormatBool(len(c.cfg.XMLLibraries) != 0)) //nolint:noctx // Operation contexts terminate the session below.

	c.cmd.Stdin, c.cmd.Stdout, c.cmd.Stderr = childInput, childOutput, io.Discard
	if err := c.cmd.Start(); err != nil {
		c.cmd = nil
		return fmt.Errorf("kalkan java: start JDK: %w", err)
	}

	_ = childInput.Close()
	_ = childOutput.Close()

	c.exited = make(chan struct{})
	go func() { _ = c.cmd.Wait(); close(c.exited) }()

	fields, err := c.call("Init", 0, 1, []byte(strconv.Itoa(c.cfg.MaxOutputSize)))
	if err != nil {
		return err
	}

	if string(fields[0]) != "kalkan-java/1" {
		return c.fail(errors.New("incompatible worker protocol"))
	}

	mode := c.cfg.RevocationMode
	if mode == "" {
		mode = "ocsp"
	}

	source, local, err := c.revocationSource(mode, c.cfg.RevocationSource)
	if err != nil {
		return err
	}

	_, err = c.call("ConfigureRevocation", 10, 0, []byte(mode), []byte(source), local)

	return err
}

func (c *Client) Close() error {
	if c.closed {
		return nil
	}

	c.closed = true
	// All worker state is in memory. Terminate the process so Close does not
	// depend on JVM shutdown hooks or provider-created threads completing.
	if c.input != nil {
		_ = c.input.Close()
	}

	if c.cmd != nil && c.exited != nil {
		_ = c.cmd.Process.Kill()
		<-c.exited
	}

	if c.output != nil {
		_ = c.output.Close()
	}

	var err error
	if c.directory != "" {
		err = os.RemoveAll(c.directory)
	}

	return err
}

func (c *Client) fail(err error) error {
	if c.failed == nil {
		c.failed = errors.Join(ErrWorkerFailed, err)
	}

	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}

	if c.input != nil {
		_ = c.input.Close()
	}

	if c.output != nil {
		_ = c.output.Close()
	}

	return c.failed
}

type workerReply struct {
	fields [][]byte
	err    error
}

func (c *Operation) call(operation string, opcode int32, expected int, fields ...[]byte) ([][]byte, error) {
	if c.failed != nil {
		return nil, c.failed
	}

	if c.closed || c.input == nil {
		return nil, ErrWorkerFailed
	}

	if err := c.ctx.Err(); err != nil {
		return nil, err
	}

	for _, field := range fields {
		if len(field) > math.MaxInt32 {
			return nil, fmt.Errorf("%w: request field exceeds Java array limit", ErrInvalidInput)
		}
	}

	done := make(chan workerReply, 1)

	go func() { values, err := c.exchange(opcode, fields); done <- workerReply{values, err} }()

	var result workerReply
	select {
	case result = <-done:
	case <-c.ctx.Done():
		err := c.ctx.Err()
		_ = c.fail(err)

		<-done

		return nil, err
	}

	if err := c.ctx.Err(); err != nil {
		_ = c.fail(err)
		return nil, err
	}

	if result.err != nil {
		var remote *Error
		if errors.As(result.err, &remote) {
			remote.Operation = operation
			if remote.Code == 4 {
				limit := c.cfg.MaxOutputSize
				if limit < 0 {
					return nil, c.fail(errors.New("invalid configured output limit"))
				}

				requested, err := strconv.ParseUint(remote.Message, 10, 64)
				if err != nil || requested <= uint64(limit) {
					return nil, c.fail(errors.New("invalid output limit response"))
				}

				return nil, &ckalkan.OutputBufferLimitError{Operation: operation, Requested: requested, Limit: uint64(limit)}
			}

			return nil, remote
		}

		return nil, c.fail(result.err)
	}

	if len(result.fields) != expected {
		return nil, c.fail(errors.New("invalid worker response field count"))
	}

	return result.fields, nil
}

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
