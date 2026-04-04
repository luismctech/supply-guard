package pip

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type pipDependency struct {
	Name       string
	Version    string
	Pinned     bool
	Line       int
	SourceFile string
}

func checkPipLockfile(dir string) []types.Finding {
	var findings []types.Finding

	hasManifest := false
	hasLockfile := false

	manifests := []string{"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile"}
	for _, m := range manifests {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			hasManifest = true
			break
		}
	}

	lockfiles := []string{"requirements.txt", "Pipfile.lock", "poetry.lock", "pdm.lock", "uv.lock"}
	for _, l := range lockfiles {
		if _, err := os.Stat(filepath.Join(dir, l)); err == nil {
			hasLockfile = true
			break
		}
	}

	if hasManifest && !hasLockfile {
		// Check for pyproject.toml without lockfile
		if _, err := os.Stat(filepath.Join(dir, "pyproject.toml")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "poetry.lock")); err != nil {
				if _, err := os.Stat(filepath.Join(dir, "pdm.lock")); err != nil {
					if _, err := os.Stat(filepath.Join(dir, "uv.lock")); err != nil {
						findings = append(findings, types.Finding{
							CheckID:     types.CheckLockfileIntegrity,
							Severity:    types.SeverityHigh,
							Ecosystem:   "pip",
							File:        "pyproject.toml",
							Title:       "No lockfile found for Python project",
							Description: "pyproject.toml exists but no lockfile (poetry.lock, pdm.lock, or uv.lock) was found. Without a lockfile, pip resolves latest compatible versions.",
							Remediation: "Use poetry, pdm, or uv to generate a lockfile. Or use 'pip freeze > requirements.txt' with pinned versions.",
						})
					}
				}
			}
		}
	}

	return findings
}

func parseRequirementsTxt(path string) []pipDependency {
	var deps []pipDependency

	f, err := os.Open(path)
	if err != nil {
		return deps
	}
	defer f.Close()

	scanner := safefile.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		dep := parsePipLine(line, lineNum)
		if dep.Name != "" {
			deps = append(deps, dep)
		}
	}

	return deps
}

func parsePipLine(line string, lineNum int) pipDependency {
	// Remove inline comments
	if idx := strings.Index(line, " #"); idx != -1 {
		line = line[:idx]
	}

	// Remove environment markers
	if idx := strings.Index(line, ";"); idx != -1 {
		line = line[:idx]
	}

	line = strings.TrimSpace(line)

	// Check for exact pinning (==)
	if idx := strings.Index(line, "=="); idx != -1 {
		return pipDependency{
			Name:    normalizePipName(line[:idx]),
			Version: line[idx:],
			Pinned:  true,
			Line:    lineNum,
		}
	}

	// Other version specifiers
	for _, op := range []string{">=", "<=", "!=", "~=", ">", "<"} {
		if idx := strings.Index(line, op); idx != -1 {
			return pipDependency{
				Name:    normalizePipName(line[:idx]),
				Version: line[idx:],
				Pinned:  false,
				Line:    lineNum,
			}
		}
	}

	// No version specified at all
	return pipDependency{
		Name:    normalizePipName(line),
		Version: "(no version)",
		Pinned:  false,
		Line:    lineNum,
	}
}

func normalizePipName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Map(func(r rune) rune {
		if r == '_' || r == '.' {
			return '-'
		}
		return r
	}, name)
	return strings.ToLower(name)
}
