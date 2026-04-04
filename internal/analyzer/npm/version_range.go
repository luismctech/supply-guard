package npm

import (
	"fmt"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkVersionRanges(pf *projectFiles, strictness string) []types.Finding {
	var findings []types.Finding

	if pf.pkg == nil {
		return findings
	}

	hasLockfile := pf.lock != nil
	threshold := check.DefaultRiskThreshold(strictness)

	for name, version := range pf.pkg.Dependencies {
		cl := check.ClassifyNpmRange(version)
		if cl.Risk < threshold {
			continue
		}
		sev := npmRangeSeverity(cl.Risk, true, hasLockfile)
		findings = append(findings, types.Finding{
			CheckID:   types.CheckVersionRange,
			Severity:  sev,
			Ecosystem: "npm",
			Package:   name,
			Version:   version,
			File:      "package.json",
			Title:     fmt.Sprintf("Permissive version range (%s): %s", cl.Risk, name),
			Description: fmt.Sprintf(
				"Package '%s' uses range '%s' (%s). %s",
				name, version, cl.Explanation, lockfileNote(hasLockfile),
			),
			Remediation: fmt.Sprintf("Pin to exact version or use tilde (~) instead: \"%s\": \"%s\"", name, suggestFix(version)),
		})
	}

	for name, version := range pf.pkg.DevDependencies {
		cl := check.ClassifyNpmRange(version)
		if cl.Risk < threshold {
			continue
		}
		sev := npmRangeSeverity(cl.Risk, false, hasLockfile)
		findings = append(findings, types.Finding{
			CheckID:   types.CheckVersionRange,
			Severity:  sev,
			Ecosystem: "npm",
			Package:   name,
			Version:   version,
			File:      "package.json",
			Title:     fmt.Sprintf("Permissive version range (%s): %s", cl.Risk, name),
			Description: fmt.Sprintf(
				"Dev dependency '%s' uses range '%s' (%s). %s",
				name, version, cl.Explanation, lockfileNote(hasLockfile),
			),
			Remediation: fmt.Sprintf("Pin to exact version or use tilde (~): \"%s\": \"%s\"", name, suggestFix(version)),
		})
	}

	return findings
}

func npmRangeSeverity(risk check.VersionRisk, isProduction, hasLockfile bool) types.Severity {
	switch risk {
	case check.RiskDangerous:
		if hasLockfile {
			return types.SeverityMedium
		}
		return types.SeverityHigh
	case check.RiskPermissive:
		if isProduction && !hasLockfile {
			return types.SeverityMedium
		}
		return types.SeverityLow
	case check.RiskConservative:
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

func lockfileNote(hasLockfile bool) string {
	if hasLockfile {
		return "A lockfile exists which mitigates this when using 'npm ci', but 'npm install' can still resolve newer versions."
	}
	return "No lockfile found -- npm install will resolve the latest version matching this range."
}

func suggestFix(version string) string {
	if len(version) > 1 && (version[0] == '^' || version[0] == '~') {
		return "~" + version[1:]
	}
	return version
}

