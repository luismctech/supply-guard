package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlbertoMZCruz/supply-guard/internal/analyzer"
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type Engine struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg}
}

func (e *Engine) Scan(ctx context.Context, dir string) (*types.ScanResult, error) {
	start := time.Now()

	result := &types.ScanResult{
		ProjectDir: dir,
		Timestamp:  start,
		Findings:   []types.Finding{},
	}

	analyzers := analyzer.All()
	if len(analyzers) == 0 {
		return nil, fmt.Errorf("no analyzers registered")
	}

	disabledChecks := e.buildDisabledSet()

	if _, err := check.GetIOCDatabase(); err != nil {
		result.Findings = append(result.Findings, types.Finding{
			CheckID:     types.CheckIOCMatch,
			Severity:    types.SeverityCritical,
			Ecosystem:   "all",
			Title:       "IOC database failed to load",
			Description: "The threat intelligence database could not be loaded: " + err.Error() + ". IOC, C2, and maintainer email checks are non-functional. This is a scanner integrity failure.",
			Remediation: "Run 'supply-guard update' to refresh the IOC database, or reinstall the binary.",
		})
	}

	for _, a := range analyzers {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("scan cancelled: %w", err)
		}

		if !e.isEcosystemEnabled(a.Ecosystem()) {
			continue
		}

		if !a.Detect(dir) {
			continue
		}

		result.Ecosystems = append(result.Ecosystems, a.Ecosystem())

		findings, err := a.Analyze(ctx, dir, e.cfg)
		if err != nil {
			return nil, fmt.Errorf("analyzer %s failed: %w", a.Name(), err)
		}

		result.Findings = append(result.Findings, findings...)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("scan cancelled: %w", err)
	}

	if !disabledChecks[string(types.CheckActionsPinning)] {
		actionIssues := check.CheckGitHubActionsPinning(dir)
		for _, issue := range actionIssues {
			relFile, _ := filepath.Rel(dir, issue.File)
			if relFile == "" {
				relFile = issue.File
			}
			result.Findings = append(result.Findings, types.Finding{
				CheckID:     types.CheckActionsPinning,
				Severity:    types.SeverityHigh,
				Ecosystem:   "ci",
				File:        relFile,
				Line:        issue.Line,
				Title:       "GitHub Action not pinned by SHA",
				Description: "Action '" + issue.Action + "' uses a mutable tag reference. The GhostActions campaign compromised 327 users by injecting malicious workflows via tag manipulation.",
				Remediation: "Pin the action to a full commit SHA instead of a tag",
			})
		}
	}

	// SG007: CI provenance workflow check (runs once globally)
	if !disabledChecks[string(types.CheckProvenance)] {
		provIssue := check.CheckCIProvenanceWorkflow(dir)
		if provIssue != nil {
			result.Findings = append(result.Findings, types.Finding{
				CheckID:     types.CheckProvenance,
				Severity:    types.SeverityInfo,
				Ecosystem:   "ci",
				File:        provIssue.File,
				Title:       "No build provenance configured",
				Description: provIssue.Description,
				Remediation: "Add SLSA provenance generation or Sigstore signing to your CI workflows. See https://slsa.dev/get-started",
			})
		}
	}

	// SG012: CI install command audit (runs once globally)
	if !disabledChecks[string(types.CheckCIInstall)] {
		ciIssues := check.CheckCIInstallCommands(dir)
		for _, issue := range ciIssues {
			relFile, _ := filepath.Rel(dir, issue.File)
			if relFile == "" {
				relFile = issue.File
			}
			result.Findings = append(result.Findings, types.Finding{
				CheckID:     types.CheckCIInstall,
				Severity:    types.SeverityHigh,
				Ecosystem:   "ci",
				File:        relFile,
				Line:        issue.Line,
				Title:       "Unsafe install command in CI",
				Description: "Command '" + issue.Command + "' found in CI workflow. " + issue.Reason,
				Remediation: issue.Reason,
			})
		}
	}

	result.Findings = e.filterFindings(result.Findings, disabledChecks)

	for _, f := range result.Findings {
		result.Summary.Add(f.Severity)
	}

	result.Duration = time.Since(start).Round(time.Millisecond).String()

	return result, nil
}

func (e *Engine) buildDisabledSet() map[string]bool {
	set := make(map[string]bool, len(e.cfg.Checks.Disabled))
	for _, id := range e.cfg.Checks.Disabled {
		set[strings.ToUpper(id)] = true
	}
	return set
}

func (e *Engine) filterFindings(findings []types.Finding, disabledChecks map[string]bool) []types.Finding {
	if len(e.cfg.Ignore) == 0 && len(e.cfg.IgnoreRules) == 0 && len(disabledChecks) == 0 {
		return findings
	}

	ignoreSet := make(map[string]bool, len(e.cfg.Ignore))
	for _, pkg := range e.cfg.Ignore {
		ignoreSet[pkg] = true
	}

	var filtered []types.Finding
	for _, f := range findings {
		if disabledChecks[string(f.CheckID)] {
			continue
		}

		if f.Package != "" && ignoreSet[f.Package] {
			continue
		}

		if e.matchesIgnoreRule(f) {
			continue
		}

		filtered = append(filtered, f)
	}
	return filtered
}

func (e *Engine) matchesIgnoreRule(f types.Finding) bool {
	for _, rule := range e.cfg.IgnoreRules {
		if rule.Check != "" && !strings.EqualFold(rule.Check, string(f.CheckID)) {
			continue
		}
		if rule.Package != "" && rule.Package != f.Package {
			continue
		}
		if rule.File != "" && !matchFile(rule.File, f.File) {
			continue
		}
		return true
	}
	return false
}

func matchFile(pattern, file string) bool {
	if pattern == file {
		return true
	}
	matched, _ := filepath.Match(pattern, file)
	return matched
}

func (e *Engine) isEcosystemEnabled(eco string) bool {
	switch eco {
	case "npm":
		return e.cfg.Ecosystems.Npm.Enabled
	case "pip":
		return e.cfg.Ecosystems.Pip.Enabled
	case "cargo":
		return e.cfg.Ecosystems.Cargo.Enabled
	case "nuget":
		return e.cfg.Ecosystems.Nuget.Enabled
	case "maven":
		return e.cfg.Ecosystems.Maven.Enabled
	case "gradle":
		return e.cfg.Ecosystems.Gradle.Enabled
	default:
		return true
	}
}
