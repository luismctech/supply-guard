package cargo

import (
	"fmt"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

const defaultCargoMaxTypoDistance = 2

func checkCargoTyposquatting(cf *cargoProjectFiles) []types.Finding {
	var findings []types.Finding

	lockFile := "Cargo.lock"

	for _, dep := range cf.deps {
		popular, dist, err := check.CheckTyposquatting("cargo", dep.Name, defaultCargoMaxTypoDistance)
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
			Ecosystem: "cargo",
			Package:   dep.Name,
			Version:   dep.Version,
			File:      lockFile,
			Title:     fmt.Sprintf("Possible typosquatting: %s (similar to %s)", dep.Name, popular),
			Description: fmt.Sprintf(
				"Crate '%s' has a Levenshtein distance of %d from popular crate '%s'. This may be a typosquatting attempt.",
				dep.Name, dist, popular,
			),
			Remediation: fmt.Sprintf("Verify you intended to use '%s' and not '%s'.", dep.Name, popular),
		})
	}

	return findings
}
