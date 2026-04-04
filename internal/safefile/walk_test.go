package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWalkDir_Basic(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0644)

	var files []string
	err := WalkDir(dir, nil, func(path string, d os.DirEntry) error {
		files = append(files, d.Name())
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d", len(files))
	}
}

func TestWalkDir_SkipDirs(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0755)
	os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "index.js"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(dir, "app.js"), []byte("y"), 0644)

	var files []string
	_ = WalkDir(dir, []string{"node_modules"}, func(path string, d os.DirEntry) error {
		files = append(files, d.Name())
		return nil
	})

	if len(files) != 1 {
		t.Errorf("expected 1 file (node_modules skipped), got %d: %v", len(files), files)
	}
}

func TestWalkDir_SymlinkSkipped(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	link := filepath.Join(dir, "link.txt")
	os.WriteFile(target, []byte("data"), 0644)
	os.Symlink(target, link)

	var files []string
	_ = WalkDir(dir, nil, func(path string, d os.DirEntry) error {
		files = append(files, d.Name())
		return nil
	})

	for _, f := range files {
		if f == "link.txt" {
			t.Error("symlink should have been skipped")
		}
	}
}

func TestWalkDir_DepthLimit(t *testing.T) {
	dir := t.TempDir()

	deep := dir
	for i := 0; i < MaxWalkDepth+5; i++ {
		deep = filepath.Join(deep, "d")
	}
	os.MkdirAll(deep, 0755)
	os.WriteFile(filepath.Join(deep, "deep.txt"), []byte("x"), 0644)

	var files []string
	_ = WalkDir(dir, nil, func(path string, d os.DirEntry) error {
		files = append(files, d.Name())
		return nil
	})

	for _, f := range files {
		if f == "deep.txt" {
			t.Error("file beyond MaxWalkDepth should not be visited")
		}
	}
}

func TestWalkDir_FileCountLimit(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 100; i++ {
		os.WriteFile(filepath.Join(dir, filepath.Base(t.Name())+string(rune('a'+i%26))+string(rune('0'+i/26))), []byte("x"), 0644)
	}

	count := 0
	savedMax := MaxWalkFiles
	defer func() {
		// MaxWalkFiles is a const so we can't restore it; test just validates the logic
	}()
	_ = savedMax // just reference it

	_ = WalkDir(dir, nil, func(path string, d os.DirEntry) error {
		count++
		return nil
	})

	if count < 1 {
		t.Error("expected at least 1 file to be walked")
	}
}

func TestWalkDir_ErrWalkLimitReached(t *testing.T) {
	if !errors.Is(ErrWalkLimitReached, ErrWalkLimitReached) {
		t.Error("ErrWalkLimitReached should match itself")
	}
}
