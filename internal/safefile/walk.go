package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	MaxWalkDepth = 20
	MaxWalkFiles = 50000
)

var ErrWalkLimitReached = errors.New("walk limit reached")

// WalkDir wraps filepath.WalkDir with depth and file count limits.
// skipDirs is a set of directory names to skip (e.g. ".git", "node_modules").
func WalkDir(root string, skipDirs []string, fn func(path string, d os.DirEntry) error) error {
	skipSet := make(map[string]bool, len(skipDirs))
	for _, d := range skipDirs {
		skipSet[d] = true
	}
	count := 0

	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		depth := strings.Count(rel, string(os.PathSeparator))
		if depth > MaxWalkDepth {
			return filepath.SkipDir
		}

		if d.IsDir() {
			if skipSet[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		count++
		if count > MaxWalkFiles {
			return ErrWalkLimitReached
		}

		return fn(path, d)
	})
}
