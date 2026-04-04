package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestCheckVersionRanges_CaretInProduction(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "test",
  "dependencies": {
    "@angular/core": "^20.3.0",
    "rxjs": "~7.8.0",
    "tslib": "2.3.0"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}

	pf := loadProjectFiles(dir)
	findings := checkVersionRanges(pf, "conservative")

	found := map[string]bool{}
	for _, f := range findings {
		found[f.Package] = true
	}

	if !found["@angular/core"] {
		t.Error("expected finding for ^20.3.0 (permissive caret)")
	}
	if found["rxjs"] {
		t.Error("rxjs uses ~7.8.0 (conservative) which should NOT be flagged with 'conservative' strictness")
	}
	if found["tslib"] {
		t.Error("tslib uses exact version which should NOT be flagged")
	}
}

func TestCheckVersionRanges_DangerousVersions(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "test",
  "dependencies": {
    "evil-pkg": "*",
    "another": "latest",
    "git-dep": "git+https://github.com/user/repo.git"
  }
}`
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644)

	pf := loadProjectFiles(dir)
	findings := checkVersionRanges(pf, "conservative")

	if len(findings) != 3 {
		t.Errorf("expected 3 dangerous findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.CheckID != types.CheckVersionRange {
			t.Errorf("expected CheckID SG011, got %s", f.CheckID)
		}
	}
}

func TestCheckVersionRanges_LockfileReducesSeverity(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name": "test", "dependencies": {"evil": "*"}}`
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644)

	pfNoLock := loadProjectFiles(dir)
	findingsNoLock := checkVersionRanges(pfNoLock, "conservative")

	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion": 3}`), 0644)
	pfWithLock := loadProjectFiles(dir)
	findingsWithLock := checkVersionRanges(pfWithLock, "conservative")

	if len(findingsNoLock) == 0 || len(findingsWithLock) == 0 {
		t.Fatal("expected findings in both cases")
	}

	// Without lockfile: dangerous -> high; with lockfile: dangerous -> medium
	if findingsNoLock[0].Severity != types.SeverityHigh {
		t.Errorf("expected high severity without lockfile, got %s", findingsNoLock[0].Severity)
	}
	if findingsWithLock[0].Severity != types.SeverityMedium {
		t.Errorf("expected medium severity with lockfile, got %s", findingsWithLock[0].Severity)
	}
}

func TestCheckVersionRanges_StrictnessPermissive(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name": "test", "dependencies": {"dep": "^1.0.0", "safe": "1.0.0"}}`
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644)

	pf := loadProjectFiles(dir)
	findings := checkVersionRanges(pf, "permissive")

	for _, f := range findings {
		if f.Package == "dep" {
			t.Error("^1.0.0 should NOT be flagged with 'permissive' strictness (only dangerous)")
		}
	}
}
