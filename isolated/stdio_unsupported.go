//go:build !linux && !darwin && !windows

package isolated

import "github.com/skarm/kalkan"

func preserveProtocolStreams() (*streams, error) { return nil, kalkan.ErrUnavailable }
