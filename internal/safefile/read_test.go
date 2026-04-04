package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFile_Regular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	want := "hello world"
	os.WriteFile(path, []byte(want), 0644)

	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestReadFile_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")
	os.WriteFile(target, []byte("secret"), 0644)
	os.Symlink(target, link)

	_, err := ReadFile(link)
	if err == nil {
		t.Fatal("expected error for symlink, got nil")
	}
}

func TestReadFile_TooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")

	f, _ := os.Create(path)
	if err := f.Truncate(MaxFileSize + 1); err != nil {
		f.Close()
		t.Skip("cannot create large sparse file")
	}
	f.Close()

	_, err := ReadFile(path)
	if err == nil {
		t.Fatal("expected error for oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected size error, got: %v", err)
	}
}

func TestReadFile_NotFound(t *testing.T) {
	_, err := ReadFile("/nonexistent/path/file.txt")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestReadFile_ExactLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.txt")
	data := make([]byte, MaxFileSize)
	os.WriteFile(path, data, 0644)

	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("file at exact limit should be readable: %v", err)
	}
	if len(got) != MaxFileSize {
		t.Errorf("expected %d bytes, got %d", MaxFileSize, len(got))
	}
}

func TestNewScanner_BufferSize(t *testing.T) {
	longLine := strings.Repeat("x", 200*1024) // 200 KB line
	r := strings.NewReader(longLine + "\n")
	s := NewScanner(r)

	if !s.Scan() {
		t.Fatalf("scanner failed to read long line: %v", s.Err())
	}
	if len(s.Text()) != 200*1024 {
		t.Errorf("expected 200KB line, got %d bytes", len(s.Text()))
	}
}
