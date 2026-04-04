package nuget

import (
	"fmt"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

const defaultNugetMaxTypoDistance = 2

func checkNuGetTyposquattingCached(nf *nugetProjectFiles) []types.Finding {
	var findings []types.Finding

	for csprojPath, refs := range nf.csprojMap {
		for _, ref := range refs {
			popular, dist, err := check.CheckTyposquatting("nuget", ref.Include, defaultNugetMaxTypoDistance)
			if err != nil || popular == "" {
				continue
			}

			severity := types.SeverityHigh
			if dist == 1 {
				severity = types.SeverityCritical
			}

			findings = append(findings, types.Finding{
				CheckID:   types.CheckTyposquatting,
				Severity:  severity,
				Ecosystem: "nuget",
				Package:   ref.Include,
				Version:   ref.Version,
				File:      csprojPath,
				Title:     "Possible typosquatting: " + ref.Include + " (similar to " + popular + ")",
				Description: fmt.Sprintf(
					"Package '%s' has a Levenshtein distance of %d from popular package '%s'. This may be a typosquatting attempt.",
					ref.Include, dist, popular,
				),
				Remediation: "Verify you intended to use '" + ref.Include + "' and not '" + popular + "'.",
			})
		}
	}

	return findings
}
