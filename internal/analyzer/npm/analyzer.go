package npm

import (
	"context"
	"os"
	"path/filepath"

	"github.com/AlbertoMZCruz/supply-guard/internal/analyzer"
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

var _ analyzer.Analyzer = (*NpmAnalyzer)(nil)

func init() {
	analyzer.Register(&NpmAnalyzer{})
}

type NpmAnalyzer struct{}

func (a *NpmAnalyzer) Name() string      { return "npm" }
func (a *NpmAnalyzer) Ecosystem() string  { return "npm" }

func (a *NpmAnalyzer) Detect(dir string) bool {
	candidates := []string{"package.json", "package-lock.json", "npm-shrinkwrap.json"}
	for _, f := range candidates {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

func (a *NpmAnalyzer) Analyze(ctx context.Context, dir string, cfg *config.Config) ([]types.Finding, error) {
	pf := loadProjectFiles(dir)
	var findings []types.Finding

	for _, w := range pf.warnings {
		findings = append(findings, types.Finding{
			CheckID:     types.CheckLockfileIntegrity,
			Severity:    types.SeverityInfo,
			Ecosystem:   "npm",
			Title:       "Parse warning",
			Description: w,
			Remediation: "Check the file for syntax errors or corruption.",
		})
	}

	findings = append(findings, checkLockfile(pf)...)
	findings = append(findings, checkInstallScripts(pf)...)
	findings = append(findings, checkIOCs(pf)...)
	findings = append(findings, checkDependencyAge(pf, cfg.Checks.DependencyAgeDays)...)
	findings = append(findings, checkPhantomDeps(pf)...)
	findings = append(findings, checkTyposquatting(pf)...)
	findings = append(findings, checkVersionRanges(pf, cfg.Checks.VersionRangeStrictness)...)
	findings = append(findings, checkMaintainerEmails(dir)...)

	npmProvIssues := check.CheckNpmIntegrity(dir)
	for _, issue := range npmProvIssues {
		sev := types.SeverityMedium
		if issue.IssueType == "git_source" {
			sev = types.SeverityHigh
		}
		findings = append(findings, types.Finding{
			CheckID:     types.CheckProvenance,
			Severity:    sev,
			Ecosystem:   "npm",
			Package:     issue.Package,
			File:        issue.File,
			Title:       "Missing provenance: " + issue.Package,
			Description: issue.Description,
			Remediation: "Run 'npm install' to regenerate the lockfile with integrity hashes, or pin the dependency to a registry source.",
		})
	}

	hardeningResult := check.CheckNpmrcHardening(dir)
	for _, missing := range hardeningResult.Missing {
		findings = append(findings, types.Finding{
			CheckID:     types.CheckConfigHardening,
			Severity:    types.SeverityMedium,
			Ecosystem:   "npm",
			File:        ".npmrc",
			Title:       "Missing security hardening in .npmrc",
			Description: "Setting " + missing + " is not configured. Install scripts are the #1 attack vector for npm malware.",
			Remediation: "Add '" + missing + "' to .npmrc or run 'supply-guard init'",
		})
	}

	return findings, nil
}
