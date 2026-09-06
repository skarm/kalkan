package isolated

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

// pipeTransport owns only the parent's endpoints. Giving exec.Cmd the child's
// *os.File endpoints avoids Cmd.Wait closing our reader before a final response
// has been consumed, as can happen with StdoutPipe.
type pipeTransport struct {
	reader *os.File
	writer *os.File
	once   sync.Once
	err    error
}

func (p *pipeTransport) Read(data []byte) (int, error)  { return p.reader.Read(data) }
func (p *pipeTransport) Write(data []byte) (int, error) { return p.writer.Write(data) }
func (p *pipeTransport) Close() error {
	p.once.Do(func() { p.err = errors.Join(p.reader.Close(), p.writer.Close()) })
	return p.err
}

// Open starts a dedicated worker and initializes its KalkanCrypt session. The
// context bounds startup only; there is no internal timeout. Canceling it after
// Open succeeds leaves the client alive. WorkerPath and WorkerArgs must start
// an application entry point that calls [RunWorker] and exits when it returns.
func Open(ctx context.Context, cfg Config) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	started := time.Now()

	// Prepare initialization metadata and borrow its raw blocks. The live client
	// does not retain passwords or certificate byte slices from configuration.
	payload, err := encodeConfig(cfg.libraryConfig())
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c, err := startProcess(cfg)
	if err != nil {
		return nil, err
	}
	// Startup owns the gate before starting Wait, so an early process exit
	// cannot close the stream ahead of its last response.
	defer func() { c.gate <- struct{}{} }()

	response, err := c.exchange(ctx, opOpen, payload)
	if err != nil {
		_ = c.stop(err)
	} else if !response.Payload.isNull() {
		err = c.failProtocol(errors.New("invalid Open acknowledgement"))
	}

	// The client has not been returned yet; Open observers can use other clients
	// but cannot reenter this instance before it is published to the caller.
	// Failed setup responses also contain useful native observations.
	if c.logger != nil || c.observer != nil {
		c.report(ctx, opOpen, started, response.Observations, err)
	}

	if err != nil {
		return nil, err
	}

	return c, nil
}

// startProcess creates private pipes and starts a supervised child without a
// shell. It returns with the startup gate held; the caller must release it.
func startProcess(cfg Config) (*Client, error) {
	childInput, input, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("kalkan isolated: create request pipe: %w", err)
	}
	defer childInput.Close()

	output, childOutput, err := os.Pipe()
	if err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("kalkan isolated: create response pipe: %w", err)
	}
	defer childOutput.Close()

	transport := &pipeTransport{reader: output, writer: input}
	// The startup context must not control the lifetime of a successfully opened
	// session. The supervisor explicitly kills and reaps the worker instead.
	command := exec.Command(cfg.WorkerPath, cfg.WorkerArgs...) //nolint:gosec,noctx // Execute the caller's explicit absolute worker path without a shell; lifecycle is supervised separately.
	command.Stdin, command.Stdout = childInput, childOutput

	c := &Client{
		gate: make(chan struct{}, 1), conn: transport, cmd: command,
		exited: make(chan struct{}), maxInputSize: cfg.MaxInputSize,
		logger: cfg.Logger, observer: cfg.Observer,
	}

	if err := command.Start(); err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("kalkan isolated: start worker: %w", err)
	}

	go c.waitProcess()

	return c, nil
}
