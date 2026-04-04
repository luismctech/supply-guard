package pip

import "path/filepath"

type pipProjectFiles struct {
	dir  string
	deps []pipDependency
}

func loadPipProjectFiles(dir string) *pipProjectFiles {
	pf := &pipProjectFiles{dir: dir}

	reqFiles := []string{"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}
	for _, f := range reqFiles {
		deps := parseRequirementsTxt(filepath.Join(dir, f))
		for i := range deps {
			deps[i].SourceFile = f
		}
		pf.deps = append(pf.deps, deps...)
	}

	return pf
}
