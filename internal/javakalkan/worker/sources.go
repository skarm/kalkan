// Package worker embeds the Java worker sources. The caller supplies all provider JARs.
package worker

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed src
var sources embed.FS

// Prepare writes the Java sources into a private session directory.
// Bootstrap compiles them in the session's JVM using the JDK 17 compiler API.
func Prepare(directory string, xmlEnabled bool) (string, error) {
	err := fs.WalkDir(sources, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if !xmlEnabled {
			switch path {
			case "src/kalkan/worker/XmlOperations.java",
				"src/kalkan/worker/XmlDocument.java",
				"src/kalkan/worker/XmlSignatures.java":
				return nil
			}
		}

		target := filepath.Join(directory, filepath.FromSlash(path))

		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}

		content, err := sources.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(target, content, 0o600)
	})
	if err != nil {
		return "", fmt.Errorf("prepare Java worker sources: %w", err)
	}

	return filepath.Join(directory, "src", "Bootstrap.java"), nil
}
