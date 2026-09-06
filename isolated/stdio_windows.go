package isolated

import (
	"os"
	"syscall"
)

func preserveProtocolStreams() (*streams, error) {
	input, err := duplicateFile(os.Stdin)
	if err != nil {
		return nil, err
	}

	output, err := duplicateFile(os.Stdout)
	if err != nil {
		_ = input.Close()
		return nil, err
	}

	transport := &streams{reader: input, writer: output}
	// Set standard handles before loading the SDK and its C runtime. The
	// protocol handles themselves are non-inheritable duplicates.
	for _, stream := range []struct {
		id   int32
		file **os.File
	}{
		{syscall.STD_INPUT_HANDLE, &os.Stdin},
		{syscall.STD_OUTPUT_HANDLE, &os.Stdout},
		{syscall.STD_ERROR_HANDLE, &os.Stderr},
	} {
		null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			_ = transport.Close()
			return nil, err
		}

		proc := syscall.NewLazyDLL("kernel32.dll").NewProc("SetStdHandle")

		result, _, callErr := proc.Call(uintptr(uint32(stream.id)), null.Fd())
		if result == 0 {
			_ = null.Close()
			_ = transport.Close()

			return nil, callErr
		}

		_ = (*stream.file).Close()
		*stream.file = null
	}

	return transport, nil
}

func duplicateFile(file *os.File) (*os.File, error) {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, err
	}

	var handle syscall.Handle
	if err := syscall.DuplicateHandle(process, syscall.Handle(file.Fd()), process, &handle, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(handle), "kalkan-protocol"), nil
}
