package npm

import (
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type packageLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]lockPackageInfo `json:"packages"`
	Dependencies    map[string]lockDepInfo     `json:"dependencies"`
}

type lockPackageInfo struct {
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
}

type lockDepInfo struct {
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
}

func checkLockfile(pf *projectFiles) []types.Finding {
	var findings []types.Finding

	if pf.pkg == nil {
		return findings
	}

	if pf.lock == nil {
		findings = append(findings, types.Finding{
			CheckID:     types.CheckLockfileIntegrity,
			Severity:    types.SeverityCritical,
			Ecosystem:   "npm",
			File:        "package.json",
			Title:       "No lockfile found",
			Description: "package-lock.json is missing. Without a lockfile, npm install resolves the latest compatible versions, which could include a compromised release (e.g. Axios 1.14.1).",
			Remediation: "Run 'npm install' to generate package-lock.json, commit it, and always use 'npm ci' in CI/CD",
		})
		return findings
	}

	allDeps := pf.allDeps()
	for name := range allDeps {
		if _, ok := pf.lockDeps[name]; !ok {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckLockfileIntegrity,
				Severity:    types.SeverityHigh,
				Ecosystem:   "npm",
				Package:     name,
				File:        "package-lock.json",
				Title:       "Dependency missing from lockfile",
				Description: "Package '" + name + "' is in package.json but not in package-lock.json. The lockfile is out of sync.",
				Remediation: "Run 'npm install' to sync the lockfile",
			})
		}
	}

	return findings
}

func extractLockDeps(lock *packageLock) map[string]string {
	deps := make(map[string]string)

	const prefix = "node_modules/"

	if lock.LockfileVersion >= 2 {
		for key, info := range lock.Packages {
			if key == "" {
				continue
			}
			name := key
			if strings.HasPrefix(key, prefix) {
				name = key[len(prefix):]
			}
			deps[name] = info.Version
		}
	}

	for name, info := range lock.Dependencies {
		deps[name] = info.Version
	}

	return deps
}
