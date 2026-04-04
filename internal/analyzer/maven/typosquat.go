package maven

import (
	"fmt"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

const defaultMavenMaxTypoDistance = 2

func checkMavenTyposquatting(mf *mavenProjectFiles) []types.Finding {
	var findings []types.Finding
	pom := mf.pom

	for _, dep := range pom.Dependencies.Dependencies {
		fullName := dep.GroupID + ":" + dep.ArtifactID

		popular, dist, err := check.CheckTyposquatting("maven", fullName, defaultMavenMaxTypoDistance)
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
			Ecosystem: "maven",
			Package:   fullName,
			Version:   dep.Version,
			File:      "pom.xml",
			Title:     "Possible typosquatting: " + fullName + " (similar to " + popular + ")",
			Description: fmt.Sprintf(
				"Artifact '%s' has a Levenshtein distance of %d from popular artifact '%s'. This may be a typosquatting attempt.",
				fullName, dist, popular,
			),
			Remediation: "Verify you intended to use '" + fullName + "' and not '" + popular + "'.",
		})
	}

	return findings
}
