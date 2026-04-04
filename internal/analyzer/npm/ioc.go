package npm

import (
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkIOCs(pf *projectFiles) []types.Finding {
	var findings []types.Finding

	if pf.lockDeps != nil {
		for name, version := range pf.lockDeps {
			match, err := check.CheckPackageIOC("npm", name, version)
			if err != nil {
				continue
			}
			if match != nil {
				findings = append(findings, types.Finding{
					CheckID:     types.CheckIOCMatch,
					Severity:    types.SeverityCritical,
					Ecosystem:   "npm",
					Package:     name,
					Version:     version,
					File:        "package-lock.json",
					Title:       "Known malicious package detected",
					Description: match.Reason,
					Remediation: "Remove this package immediately and audit your systems for compromise",
				})
			}
		}
		return findings
	}

	allDeps := pf.allDeps()
	for name, version := range allDeps {
		match, err := check.CheckPackageIOC("npm", name, version)
		if err != nil {
			continue
		}
		if match != nil {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckIOCMatch,
				Severity:    types.SeverityCritical,
				Ecosystem:   "npm",
				Package:     name,
				Version:     version,
				File:        "package.json",
				Title:       "Known malicious package detected",
				Description: match.Reason,
				Remediation: "Remove this package immediately and audit your systems for compromise",
			})
		}
	}

	return findings
}
