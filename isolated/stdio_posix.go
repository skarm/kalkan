//go:build linux || darwin

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

	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	defer null.Close()
	// Go and C still use fd 0/1/2, which now refer to null. The private copies
	// carry only protocol bytes and are closed when a subprocess calls exec.
	for _, descriptor := range []int{0, 1, 2} {
		if err := redirectDescriptor(int(null.Fd()), descriptor); err != nil {
			_ = transport.Close()
			return nil, err
		}
	}

	return transport, nil
}

func duplicateFile(file *os.File) (*os.File, error) {
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		return nil, err
	}

	syscall.CloseOnExec(fd)
	// Inherited stdin/stdout pipes are blocking. Register their duplicates
	// with Go's poller so Close interrupts an outstanding protocol read/write.
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}

	return os.NewFile(uintptr(fd), "kalkan-protocol"), nil
}
