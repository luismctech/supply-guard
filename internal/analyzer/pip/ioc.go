package pip

import (
	"fmt"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkPipIOCsCached(pf *pipProjectFiles) []types.Finding {
	var findings []types.Finding

	for _, dep := range pf.deps {
		match, err := check.CheckPackageIOC("pip", dep.Name, dep.Version)
		if err != nil {
			continue
		}
		if match != nil {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckIOCMatch,
				Severity:    types.SeverityCritical,
				Ecosystem:   "pip",
				Package:     dep.Name,
				Version:     dep.Version,
				File:        dep.SourceFile,
				Line:        dep.Line,
				Title:       "Known malicious package detected",
				Description: match.Reason,
				Remediation: "Remove this package immediately and audit your systems for compromise",
			})
		}
	}

	return findings
}

func checkPipTyposquattingCached(pf *pipProjectFiles) []types.Finding {
	var findings []types.Finding

	for _, dep := range pf.deps {
		similarTo, dist, err := check.CheckTyposquatting("pip", dep.Name, 2)
		if err != nil {
			continue
		}
		if similarTo != "" {
			severity := types.SeverityHigh
			if dist == 1 {
				severity = types.SeverityCritical
			}
			findings = append(findings, types.Finding{
				CheckID:   types.CheckTyposquatting,
				Severity:  severity,
				Ecosystem: "pip",
				Package:   dep.Name,
				File:      dep.SourceFile,
				Line:      dep.Line,
				Title:     fmt.Sprintf("Possible typosquatting: '%s' similar to '%s'", dep.Name, similarTo),
				Description: fmt.Sprintf(
					"Package '%s' has an edit distance of %d from popular package '%s'.",
					dep.Name, dist, similarTo,
				),
				Remediation: fmt.Sprintf("Verify you intended to install '%s' and not '%s'", dep.Name, similarTo),
			})
		}
	}

	return findings
}

