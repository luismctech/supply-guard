package npm

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkDependencyAge(pf *projectFiles, minAgeDays int) []types.Finding {
	var findings []types.Finding

	if minAgeDays <= 0 || pf.lockDeps == nil {
		return findings
	}

	now := time.Now()
	nodeModules := filepath.Join(pf.dir, "node_modules")

	for name, version := range pf.lockDeps {
		if name == "" {
			continue
		}

		modTime := getPackageModTime(nodeModules, name)
		if modTime.IsZero() {
			continue
		}

		ageDays := int(now.Sub(modTime).Hours() / 24)
		if ageDays < minAgeDays {
			findings = append(findings, types.Finding{
				CheckID:   types.CheckDependencyAge,
				Severity:  types.SeverityMedium,
				Ecosystem: "npm",
				Package:   name,
				Version:   version,
				File:      "package-lock.json",
				Title:     fmt.Sprintf("Dependency installed %d days ago (threshold: %d)", ageDays, minAgeDays),
				Description: fmt.Sprintf(
					"Package %s@%s was installed %d days ago. "+
						"A 7-day cooldown would have prevented 8 out of 10 major supply chain attacks in 2025. "+
						"Note: age is estimated from filesystem timestamps.",
					name, version, ageDays,
				),
				Remediation: fmt.Sprintf("Wait until the package is at least %d days old before adopting", minAgeDays),
			})
		}
	}

	return findings
}

// getPackageModTime returns the modification time of the package's
// directory in node_modules as a proxy for install/publish date.
func getPackageModTime(nodeModules, name string) time.Time {
	pkgDir := filepath.Join(nodeModules, name)
	info, err := os.Stat(pkgDir)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
