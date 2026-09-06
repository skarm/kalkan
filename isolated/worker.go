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

// RunWorker serves SDK requests over the stdin/stdout pipes supplied by [Open].
// Call it in the application's worker branch, in a dedicated child process,
// before starting normal services. Use os.Executable for [Config.WorkerPath]
// and pass the application's worker argument in [Config.WorkerArgs].
//
// RunWorker redirects the process's standard streams to null before loading the
// SDK. It returns on session close, transport failure, or context cancellation.
// Exit the process immediately when it returns,
// even on success: a native call may still be stuck in a goroutine.
func RunWorker(ctx context.Context) error {
	transport, err := preserveProtocolStreams()
	if err != nil {
		return err
	}
	defer transport.Close()

	return serve(ctx, transport, openLibrary)
}

func openLibrary(ctx context.Context, cfg libraryConfig, observer kalkan.Observer) (workerSession, error) {
	if observer == nil {
		return kalkan.Open(ctx, cfg.Options()...)
	}

	closed := make(chan struct{})

	var once sync.Once

	options := append(cfg.Options(), kalkan.WithObserver(func(ctx context.Context, value kalkan.OperationObservation) {
		observer(ctx, value)

		if value.Operation == opClose {
			once.Do(func() { close(closed) })
		}
	}))

	client, err := kalkan.Open(ctx, options...)
	if err != nil {
		return nil, err
	}

	return &observedSession{Client: client, closed: closed}, nil
}

// kalkan.Close publishes its result before reporting its final observation.
// Wait for that callback before the worker snapshots observations and exits.
type observedSession struct {
	*kalkan.Client
	closed <-chan struct{}
}

func (s *observedSession) Close() error {
	err := s.Client.Close()
	<-s.closed

	return err
}

type streams struct {
	reader io.ReadCloser
	writer io.WriteCloser
}

func (s *streams) Read(data []byte) (int, error)  { return s.reader.Read(data) }
func (s *streams) Write(data []byte) (int, error) { return s.writer.Write(data) }
func (s *streams) Close() error                   { return errors.Join(s.reader.Close(), s.writer.Close()) }

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
	defer cancel()

	incoming := make(chan readResult)

	go func() {
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
	}()

	var client workerSession

	collector := &observations{}

	var pending <-chan operationResult

	expected := uint64(1)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case read := <-incoming:
			if read.err != nil {
				// Return without native Close: a hung SDK call must not keep an
				// orphan worker alive after the parent closes its request pipe.
				return read.err
			}

			if pending != nil || read.message.ID != expected || read.message.Error != nil || len(read.message.Observations) != 0 {
				return fmt.Errorf("%w: unexpected request sequence", ErrProtocol)
			}

			expected++
			done := make(chan operationResult, 1)

			pending = done
			go func(message message, session workerSession) {
				done <- execute(message, session, factory, collector)
			}(read.message, client)
		case result := <-pending:
			pending = nil

			client = result.client
			if err := writeResponse(transport, result.message); err != nil {
				return err
			}

			if result.quit {
				return nil
			}
		}
	}
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
	// No response bytes were written. Return a small typed error without
	// pretending that a completed native operation was rolled back.
	message.Payload, message.Observations = wirePayload{}, nil
	message.Error = errMetadataTooLarge

	return writeMessage(writer, message)
}
