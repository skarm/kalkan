//go:build !(linux && cgo) && !(windows && amd64)

package kalkancrypt

const driverAvailable = false

func openDriver(_ string) (driver, error) { return nil, ErrUnavailable }
