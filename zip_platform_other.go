//go:build !darwin && !linux

package kalkan

import (
	"os"
)

func validateCreatedOutput(string, os.FileInfo, outputPolicy) error {
	return nil
}

func outputDirectoryIsPrivate(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir()
}
