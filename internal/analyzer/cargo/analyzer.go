package cargo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/analyzer"
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

var _ analyzer.Analyzer = (*CargoAnalyzer)(nil)

func init() {
	analyzer.Register(&CargoAnalyzer{})
}

type CargoAnalyzer struct{}

func (a *CargoAnalyzer) Name() string      { return "cargo" }
func (a *CargoAnalyzer) Ecosystem() string  { return "cargo" }

func (a *CargoAnalyzer) Detect(dir string) bool {
	candidates := []string{"Cargo.toml", "Cargo.lock"}
	for _, f := range candidates {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

func (a *CargoAnalyzer) Analyze(ctx context.Context, dir string, cfg *config.Config) ([]types.Finding, error) {
	cf := loadCargoProjectFiles(dir)
	var findings []types.Finding

	findings = append(findings, checkCargoLockfile(dir)...)
	findings = append(findings, checkCargoIOCs(cf)...)
	findings = append(findings, checkCargoBuildScripts(dir)...)
	findings = append(findings, checkCargoVersionRanges(dir, cfg.Checks.VersionRangeStrictness)...)
	findings = append(findings, checkCargoProvenance(dir)...)
	findings = append(findings, checkCargoTyposquatting(cf)...)

	return findings, nil
}

func checkCargoLockfile(dir string) []types.Finding {
	var findings []types.Finding

	tomlPath := filepath.Join(dir, "Cargo.toml")
	lockPath := filepath.Join(dir, "Cargo.lock")

	if _, err := os.Stat(tomlPath); err != nil {
		return findings
	}

	if _, err := os.Stat(lockPath); err != nil {
		findings = append(findings, types.Finding{
			CheckID:     types.CheckLockfileIntegrity,
			Severity:    types.SeverityHigh,
			Ecosystem:   "cargo",
			File:        "Cargo.toml",
			Title:       "No Cargo.lock found",
			Description: "Cargo.toml exists but Cargo.lock is missing. Without a lockfile, cargo will resolve latest compatible versions.",
			Remediation: "Run 'cargo generate-lockfile' and commit Cargo.lock",
		})
	}

	return findings
}

type cargoDep struct {
	Name    string
	Version string
}

func parseCargoLock(path string) []cargoDep {
	var deps []cargoDep

	f, err := os.Open(path)
	if err != nil {
		return deps
	}
	defer f.Close()

	scanner := safefile.NewScanner(f)
	var currentName, currentVersion string
	inPackage := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			if inPackage && currentName != "" {
				deps = append(deps, cargoDep{Name: currentName, Version: currentVersion})
			}
			currentName = ""
			currentVersion = ""
			inPackage = true
			continue
		}

		if inPackage {
			if strings.HasPrefix(line, "name = ") {
				currentName = extractTomlString(line)
			} else if strings.HasPrefix(line, "version = ") {
				currentVersion = extractTomlString(line)
			}
		}
	}

	if inPackage && currentName != "" {
		deps = append(deps, cargoDep{Name: currentName, Version: currentVersion})
	}

	return deps
}

func extractTomlString(line string) string {
	idx := strings.Index(line, "\"")
	if idx == -1 {
		return ""
	}
	end := strings.Index(line[idx+1:], "\"")
	if end == -1 {
		return ""
	}
	return line[idx+1 : idx+1+end]
}

func checkCargoIOCs(cf *cargoProjectFiles) []types.Finding {
	var findings []types.Finding

	for _, dep := range cf.deps {
		match, err := check.CheckPackageIOC("cargo", dep.Name, dep.Version)
		if err != nil {
			continue
		}
		if match != nil {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckIOCMatch,
				Severity:    types.SeverityCritical,
				Ecosystem:   "cargo",
				Package:     dep.Name,
				Version:     dep.Version,
				File:        "Cargo.lock",
				Title:       "Known malicious crate detected",
				Description: match.Reason,
				Remediation: "Remove this crate immediately and audit your systems",
			})
		}
	}

	return findings
}

func checkCargoBuildScripts(dir string) []types.Finding {
	var findings []types.Finding

	buildScript := filepath.Join(dir, "build.rs")
	data, err := safefile.ReadFile(buildScript)
	if err != nil {
		return findings
	}

	content := string(data)

	if strings.Contains(content, "std::fs::write") {
		findings = append(findings, types.Finding{
			CheckID:     types.CheckInstallScripts,
			Severity:    types.SeverityMedium,
			Ecosystem:   "cargo",
			File:        "build.rs",
			Title:       "Build script uses filesystem write API: std::fs::write",
			Description: "build.rs writes to the filesystem during the build phase, which could indicate tampering.",
			Remediation: "Review build.rs to ensure it only performs legitimate build tasks",
		})
	}

	netIssues := check.ScanForNetworkCalls(content, "cargo")
	for _, issue := range netIssues {
		sev := types.SeverityHigh
		if issue.Risk == "critical" {
			sev = types.SeverityCritical
		}
		findings = append(findings, types.Finding{
			CheckID:     types.CheckNetworkCalls,
			Severity:    sev,
			Ecosystem:   "cargo",
			File:        "build.rs",
			Title:       fmt.Sprintf("Build script contains %s pattern: %s", issue.Category, issue.Pattern),
			Description: "build.rs contains a " + issue.Category + " pattern (" + issue.Pattern + ") that may indicate network access or code execution during build.",
			Remediation: "Review build.rs to ensure it only performs legitimate build tasks",
		})
	}

	return findings
}
