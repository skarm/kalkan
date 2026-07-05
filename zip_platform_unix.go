//go:build darwin || linux

package kalkan

import (
	"fmt"
	"os"
	"syscall"
)

func validateCreatedOutput(path string, info os.FileInfo, policy outputPolicy) error {
	mode := info.Mode().Perm()
	if outputDirectoryIsPrivate(policy.dir) {
		if mode&0o002 != 0 {
			return fmt.Errorf("%w: %s is writable by others: %s", ErrInvalidInput, policy.label, path)
		}
	} else if mode&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others: %s", ErrInvalidInput, policy.label, path)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}

	if int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("%w: %s owner does not match current user: %s", ErrInvalidInput, policy.label, path)
	}

	return nil
}

func outputDirectoryIsPrivate(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return false
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	return int64(stat.Uid) == int64(os.Geteuid())
}
