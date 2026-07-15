package kalkan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func zipOutputPlan(outputPath string) (zipPlan, error) {
	outputPath, err := validateNativePathString("ZIP output path", outputPath)
	if err != nil {
		return zipPlan{}, err
	}

	outDir := filepath.Dir(outputPath)
	base := filepath.Base(outputPath)

	if base == "." || base == string(filepath.Separator) || base == "" {
		return zipPlan{}, fmt.Errorf("%w: ZIP output file name is empty", ErrInvalidInput)
	}

	ext := filepath.Ext(base)
	if !strings.EqualFold(ext, ".zip") {
		return zipPlan{}, fmt.Errorf("%w: ZIP output extension must be .zip", ErrInvalidInput)
	}

	nativeName := strings.TrimSuffix(base, ext)
	if nativeName == "" {
		return zipPlan{}, fmt.Errorf("%w: ZIP output file name is empty", ErrInvalidInput)
	}

	return zipPlan{
		requestedPath: outputPath,
		desiredPath:   filepath.Join(outDir, nativeName+".zip"),
		nativeName:    nativeName,
		outDir:        outDir,
	}, nil
}

func ensureZIPOutputAbsent(plan zipPlan) error {
	for _, path := range plan.outputPaths() {
		_, err := os.Lstat(path)
		if err == nil {
			return fmt.Errorf("%w: ZIP output already exists: %s", ErrInvalidInput, path)
		}

		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

func createdZIPPath(plan zipPlan) (string, error) {
	path, info, err := statCreatedZIPPath(plan)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("kalkan: ZIP output was not created at %s", plan.desiredPath)
	}

	if err != nil {
		return "", err
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("kalkan: ZIP output is not a regular file: %s", path)
	}

	return path, nil
}

func (p zipPlan) outputPaths() []string {
	if p.requestedPath == "" || p.requestedPath == p.desiredPath {
		return []string{p.desiredPath}
	}

	return []string{p.requestedPath, p.desiredPath}
}

func statCreatedZIPPath(plan zipPlan) (string, os.FileInfo, error) {
	for _, path := range []string{plan.desiredPath, plan.requestedPath} {
		if path == "" {
			continue
		}

		info, err := os.Lstat(path)
		if err == nil {
			return path, info, nil
		}

		if !errors.Is(err, os.ErrNotExist) {
			return path, nil, err
		}
	}

	return plan.desiredPath, nil, os.ErrNotExist
}
