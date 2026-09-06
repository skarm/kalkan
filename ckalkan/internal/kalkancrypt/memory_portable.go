//go:build !(linux && amd64 && cgo)

package kalkancrypt

// nativeInt matches the Windows ABI and keeps buffer helpers available on
// builds without a native driver.
type nativeInt = int32
