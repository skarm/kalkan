// Package kalkancrypt contains the private KalkanCrypt ABI boundary.
//
// The package has a small common Go core plus one platform driver. The common
// files define Context, request/result DTOs, and method routing; they compile on
// every platform. Platform driver files own dynamic loading and native ABI calls.
package kalkancrypt
