package isolated

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/skarm/kalkan"
)

// workerSession is the worker's SDK session.
type workerSession interface {
	sdkClient
	Close() error
}

// workerFactory initializes an SDK session.
type workerFactory func(context.Context, libraryConfig, kalkan.Observer) (workerSession, error)

// RunWorker serves SDK requests over the stdin and stdout pipes from [Open].
// Call it in the application's worker branch in a dedicated child process.
// Call it before normal services start.
// Use the path from os.Executable for Config.WorkerPath.
// Pass the worker argument in Config.WorkerArgs.
//
// RunWorker redirects standard streams to null before the SDK loads.
// It returns on session close, transport failure, or context cancellation.
// Exit the process immediately when RunWorker returns, even on success.
// A native call can still be stuck in a goroutine.
func RunWorker(ctx context.Context) error {
	transport, err := preserveProtocolStreams()
	if err != nil {
		return err
	}

	return serve(ctx, transport, openLibrary)
}

func openLibrary(ctx context.Context, cfg libraryConfig, observer kalkan.Observer) (workerSession, error) {
	if observer == nil {
		return kalkan.Open(ctx, cfg.Options()...)
	}

	closed := make(chan struct{})
	sawInit := false

	var once sync.Once

	options := append(cfg.Options(), kalkan.WithObserver(func(ctx context.Context, value kalkan.OperationObservation) {
		if value.Operation == "Init" {
			// Init reports synchronously before kalkan.Open can return.
			sawInit = true
		}

		observer(ctx, value)

		if value.Operation == opClose {
			once.Do(func() { close(closed) })
		}
	}))

	client, err := kalkan.Open(ctx, options...)
	if err != nil {
		if sawInit {
			// A failed Open releases its initialized session, but Close can return
			// before its observer callback.
			// Wait for that observation before execute reads the collector and the
			// worker exits.
			// execute uses a background context, so each created session reaches Init.
			// Failures before Init need no Close callback and must not wait.
			<-closed
		}

		return nil, err
	}

	return &observedSession{Client: client, closed: closed}, nil
}

// observedSession waits for the Close observation after kalkan.Close returns
// its saved result.
// The worker must receive that observation before it reads the collector and exits.
type observedSession struct {
	*kalkan.Client
	closed <-chan struct{}
}

// Close closes the session and waits for its final observation. It returns the
// session's close error.
func (s *observedSession) Close() error {
	err := s.Client.Close()
	<-s.closed

	return err
}

type streams struct {
	reader io.ReadCloser
	writer io.WriteCloser
}

// Read reads from the session's input stream into data.
func (s *streams) Read(data []byte) (int, error) { return s.reader.Read(data) }

// Write writes data to the session's output stream.
func (s *streams) Write(data []byte) (int, error) { return s.writer.Write(data) }

// Close closes both session streams and returns their combined errors.
func (s *streams) Close() error { return errors.Join(s.reader.Close(), s.writer.Close()) }

type readResult struct {
	message message
	err     error
}

type operationResult struct {
	message message
	client  workerSession
	quit    bool
}

func serve(ctx context.Context, transport io.ReadWriteCloser, factory workerFactory) error {
	ctx, cancel := context.WithCancel(ctx)

	incoming := make(chan readResult)

	var (
		ioWorkers sync.WaitGroup
		writing   <-chan error
	)

	// serve owns the transport.
	// Transport closure interrupts both I/O goroutines.
	// Native execution can remain stuck until the process exits.
	defer func() {
		cancel()

		_ = transport.Close()

		ioWorkers.Wait()
	}()

	ioWorkers.Go(func() {
		for {
			message, err := readMessage(transport)
			select {
			case incoming <- readResult{message, err}:
			case <-ctx.Done():
				return
			}

			if err != nil {
				return
			}
		}
	})

	collector := &observations{}

	var (
		client  workerSession
		pending <-chan operationResult
		next    *message
		quit    bool
	)

	expected := uint64(1)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case read := <-incoming:
			if read.err != nil {
				// Return without native Close.
				// A hung SDK call must not keep an orphan worker alive after the parent
				// closes its request pipe.
				return read.err
			}

			if pending != nil || next != nil || read.message.ID != expected || read.message.Error != nil || len(read.message.Observations) != 0 {
				return fmt.Errorf("%w: unexpected request sequence", ErrProtocol)
			}

			expected++

			if writing != nil {
				// The parent can read the final response and send its next request before
				// the writer reports completion.
				// Defer that request until completion.
				// Continue to check for EOF and cancellation.
				next = &read.message
				continue
			}

			pending = executeAsync(read.message, client, factory, collector)
		case result := <-pending:
			pending = nil

			client = result.client
			quit = result.quit
			done := make(chan error, 1)

			writing = done

			ioWorkers.Go(func() { done <- writeResponse(transport, result.message) })
		case err := <-writing:
			writing = nil

			if err != nil {
				return err
			}

			if quit {
				return nil
			}

			if next != nil {
				pending = executeAsync(*next, client, factory, collector)
				next = nil
			}
		}
	}
}

func executeAsync(request message, client workerSession, factory workerFactory, collector *observations) <-chan operationResult {
	done := make(chan operationResult, 1)
	go func() { done <- execute(request, client, factory, collector) }()

	return done
}

type observations struct {
	mu     sync.Mutex
	values []kalkan.OperationObservation
}

func (o *observations) append(_ context.Context, value kalkan.OperationObservation) {
	o.mu.Lock()
	o.values = append(o.values, value)
	o.mu.Unlock()
}

func (o *observations) take() []kalkan.OperationObservation {
	if o == nil {
		return nil
	}

	o.mu.Lock()
	values := o.values
	o.values = nil
	o.mu.Unlock()

	return values
}

func execute(request message, client workerSession, factory workerFactory, collector *observations) operationResult {
	response := message{ID: request.ID, Operation: request.Operation, Payload: nullPayload()}
	result := operationResult{message: response, client: client}

	var err error

	switch request.Operation {
	case opOpen:
		if client != nil {
			err = fmt.Errorf("%w: session already open", ErrProtocol)
			break
		}

		cfg, decodeErr := decodeConfig(request.Payload)
		if decodeErr != nil {
			err = fmt.Errorf("%w: invalid Open configuration", ErrProtocol)
			break
		}

		var observer kalkan.Observer
		if cfg.CollectObservations && collector != nil {
			observer = collector.append
		}

		client, err = factory(context.Background(), cfg, observer)
		result.client = client
		result.quit = err != nil
	case opClose:
		if !request.Payload.isNull() {
			err = fmt.Errorf("%w: invalid Close payload", ErrProtocol)
			break
		}

		if client == nil {
			err = fmt.Errorf("%w: no session", ErrProtocol)
			break
		}

		err = client.Close()
		result.quit = true
	default:
		if client == nil {
			err = fmt.Errorf("%w: Open is required", ErrProtocol)
			break
		}

		result.message.Payload, err = dispatch(context.Background(), client, request.Operation, request.Payload)
	}

	if errors.Is(err, ErrProtocol) {
		result.quit = true
	}

	result.message.Error = err
	result.message.Observations = collector.take()

	return result
}

func writeResponse(writer io.Writer, message message) error {
	err := writeMessage(writer, message)
	if !errors.Is(err, errMetadataTooLarge) {
		return err
	}
	// The writer sent no response bytes.
	// Return a small typed error.
	// A completed native operation can still have external effects.
	message.Payload, message.Observations = wirePayload{}, nil
	message.Error = errMetadataTooLarge

	return writeMessage(writer, message)
}
