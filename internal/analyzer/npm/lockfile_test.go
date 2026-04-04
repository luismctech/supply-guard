package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestCheckLockfile_Missing(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"test","dependencies":{"express":"^4.0.0"}}`), 0644)

	pf := loadProjectFiles(dir)
	findings := checkLockfile(pf)
	if len(findings) == 0 {
		t.Fatal("expected finding for missing lockfile")
	}
	if findings[0].CheckID != types.CheckLockfileIntegrity {
		t.Errorf("expected CheckID %s, got %s", types.CheckLockfileIntegrity, findings[0].CheckID)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected severity critical, got %s", findings[0].Severity)
	}
}

func TestCheckLockfile_Present(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"test","dependencies":{"express":"^4.0.0"}}`
	lock := `{"lockfileVersion":2,"packages":{"node_modules/express":{"version":"4.18.2"}},"dependencies":{"express":{"version":"4.18.2"}}}`

	os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0644)

	pf := loadProjectFiles(dir)
	findings := checkLockfile(pf)
	for _, f := range findings {
		if f.Title == "No lockfile found" {
			t.Error("should not report missing lockfile when it exists")
		}
	}
}

func TestCheckLockfile_OutOfSync(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"test","dependencies":{"express":"^4.0.0","axios":"^1.0.0"}}`
	lock := `{"lockfileVersion":2,"packages":{"node_modules/express":{"version":"4.18.2"}},"dependencies":{"express":{"version":"4.18.2"}}}`

	os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0644)

	pf := loadProjectFiles(dir)
	findings := checkLockfile(pf)
	found := false
	for _, f := range findings {
		if f.Package == "axios" && f.Title == "Dependency missing from lockfile" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for axios missing from lockfile")
	}
}
