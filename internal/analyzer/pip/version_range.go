package pip

import (
	"fmt"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkPipVersionRangesCached(pf *pipProjectFiles, strictness string) []types.Finding {
	var findings []types.Finding

	threshold := check.DefaultRiskThreshold(strictness)

	for _, dep := range pf.deps {
		cl := check.ClassifyPipRange(dep.Version)
		if cl.Risk < threshold {
			continue
		}
		sev := check.DefaultRangeSeverity(cl.Risk)
		findings = append(findings, types.Finding{
			CheckID:   types.CheckVersionRange,
			Severity:  sev,
			Ecosystem: "pip",
			Package:   dep.Name,
			Version:   dep.Version,
			File:      dep.SourceFile,
			Line:      dep.Line,
			Title:     fmt.Sprintf("Permissive version range (%s): %s", cl.Risk, dep.Name),
			Description: fmt.Sprintf(
				"Package '%s' uses '%s' (%s). Without exact pinning, pip may install a compromised newer version.",
				dep.Name, dep.Version, cl.Explanation,
			),
			Remediation: fmt.Sprintf("Pin to exact version: %s==<version>", dep.Name),
		})
	}

	return findings
}
