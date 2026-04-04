package safefile

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"syscall"
)

const (
	MaxFileSize    = 50 * 1024 * 1024 // 50 MB
	ScannerBufSize = 256 * 1024       // 256 KB
)

// NewScanner creates a bufio.Scanner with an expanded buffer to handle long lines.
func NewScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, ScannerBufSize), ScannerBufSize)
	return s
}

// ReadFile opens a file with O_NOFOLLOW to prevent symlink races, then
// validates size before reading. Returns an error for symlinks or oversized files.
func ReadFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to read symlink: %s", path)
	}
	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("file exceeds %d byte limit: %s (%d bytes)", MaxFileSize, path, info.Size())
	}

	return io.ReadAll(io.LimitReader(f, MaxFileSize+1))
}
