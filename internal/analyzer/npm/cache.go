package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
)

// fullPackageJSON merges all fields that different check functions need
// from the root package.json, so it's parsed only once per scan.
type fullPackageJSON struct {
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Scripts         map[string]string `json:"scripts"`
}

type projectFiles struct {
	dir      string
	pkg      *fullPackageJSON
	lock     *packageLock
	lockDeps map[string]string
	warnings []string
}

func loadProjectFiles(dir string) *projectFiles {
	pf := &projectFiles{dir: dir}

	pkgPath := filepath.Join(dir, "package.json")
	if data, err := safefile.ReadFile(pkgPath); err == nil {
		var pkg fullPackageJSON
		if err := json.Unmarshal(data, &pkg); err != nil {
			pf.warnings = append(pf.warnings, fmt.Sprintf("package.json exists but could not be parsed: %v", err))
		} else {
			pf.pkg = &pkg
		}
	}

	lockPath := filepath.Join(dir, "package-lock.json")
	if _, statErr := os.Stat(lockPath); statErr == nil {
		if data, err := safefile.ReadFile(lockPath); err != nil {
			pf.warnings = append(pf.warnings, fmt.Sprintf("package-lock.json exists but could not be read: %v", err))
		} else {
			var lock packageLock
			if err := json.Unmarshal(data, &lock); err != nil {
				pf.warnings = append(pf.warnings, fmt.Sprintf("package-lock.json could not be parsed: %v", err))
			} else {
				pf.lock = &lock
				pf.lockDeps = extractLockDeps(&lock)
			}
		}
	}

	return pf
}

func (pf *projectFiles) allDeps() map[string]string {
	if pf.pkg == nil {
		return nil
	}
	all := make(map[string]string, len(pf.pkg.Dependencies)+len(pf.pkg.DevDependencies))
	for k, v := range pf.pkg.Dependencies {
		all[k] = v
	}
	for k, v := range pf.pkg.DevDependencies {
		all[k] = v
	}
	return all
}
