package pip

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckPipLockfile_MissingLockfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[build-system]\n"), 0644); err != nil {
		t.Fatal(err)
	}

	findings := checkPipLockfile(dir)
	found := false
	for _, f := range findings {
		if f.Title == "No lockfile found for Python project" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'No lockfile found' finding for pyproject.toml without lock")
	}
}

func TestCheckPipVersionRanges_UnpinnedDeps(t *testing.T) {
	dir := t.TempDir()
	requirements := "flask>=2.0.0\nrequests==2.31.0\nnumpy\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(requirements), 0644); err != nil {
		t.Fatal(err)
	}

	pf := loadPipProjectFiles(dir)
	findings := checkPipVersionRangesCached(pf, "conservative")
	if len(findings) < 2 {
		t.Errorf("expected at least 2 version range findings, got %d", len(findings))
	}
}

func TestCheckPipVersionRanges_AllPinned(t *testing.T) {
	dir := t.TempDir()
	requirements := "flask==2.3.0\nrequests==2.31.0\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(requirements), 0644); err != nil {
		t.Fatal(err)
	}

	pf := loadPipProjectFiles(dir)
	findings := checkPipVersionRangesCached(pf, "conservative")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for pinned deps, got %d", len(findings))
	}
}
