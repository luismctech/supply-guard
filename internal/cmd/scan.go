package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/engine"
	"github.com/AlbertoMZCruz/supply-guard/internal/report"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"

	_ "github.com/AlbertoMZCruz/supply-guard/internal/analyzer/cargo"
	_ "github.com/AlbertoMZCruz/supply-guard/internal/analyzer/maven"
	_ "github.com/AlbertoMZCruz/supply-guard/internal/analyzer/npm"
	_ "github.com/AlbertoMZCruz/supply-guard/internal/analyzer/nuget"
	_ "github.com/AlbertoMZCruz/supply-guard/internal/analyzer/pip"
)

// ErrFindingsExceedThreshold signals that findings exceeded the --fail-on threshold.
var ErrFindingsExceedThreshold = errors.New("findings exceed severity threshold")

// SeverityExitError carries a granular exit code based on highest severity found.
type SeverityExitError struct {
	Code    int
	Message string
}

func (e *SeverityExitError) Error() string { return e.Message }

var scanCmd = &cobra.Command{
	Use:   "scan [directory]",
	Short: "Scan a project for supply chain threats",
	Long: `Scan analyzes a project directory for supply chain security issues:
  - Lockfile integrity and consistency
  - Malicious install scripts
  - Known malicious packages (IOC matching)
  - Suspiciously new dependencies
  - Phantom dependencies
  - Typosquatting detection
  - Package manager hardening`,
	Args:          cobra.MaximumNArgs(1),
	RunE:          runScan,
	SilenceErrors: true,
	SilenceUsage:  true,
}

var (
	baselineFile string
	watchMode    bool
)

func init() {
	scanCmd.Flags().StringVar(&baselineFile, "baseline", "", "path to a previous scan result JSON for diffing (shows only new findings)")
	scanCmd.Flags().BoolVar(&watchMode, "watch", false, "watch for file changes and re-scan (outputs stream-json events)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	if watchMode {
		return runWatch(dir)
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}

	linfo, err := os.Lstat(absDir)
	if err != nil {
		return fmt.Errorf("not a valid directory: %s", absDir)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	if linfo.Mode()&os.ModeSymlink != 0 {
		if !cfg.Quiet {
			fmt.Fprintf(os.Stderr, "⚠  Warning: scan target %s is a symlink. Resolving to real path.\n", absDir)
		}
		absDir, err = filepath.EvalSymlinks(absDir)
		if err != nil {
			return fmt.Errorf("cannot resolve symlink: %w", err)
		}
	}
	info, err := os.Stat(absDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("not a valid directory: %s", absDir)
	}

	if !cfg.Quiet {
		WarnIfUntrustedConfig(absDir)
	}

	eng := engine.New(cfg)
	result, err := eng.Scan(context.Background(), absDir)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	for i := range result.Findings {
		result.Findings[i].Fingerprint = result.Findings[i].ComputeFingerprint()
	}
	report.EnrichWithFixes(result.Findings)

	if baselineFile != "" {
		result.Findings, err = filterNewFindings(result.Findings, baselineFile)
		if err != nil {
			return fmt.Errorf("baseline error: %w", err)
		}
		result.Summary = types.Summary{}
		for _, f := range result.Findings {
			result.Summary.Add(f.Severity)
		}
	}

	reporter, err := report.Get(cfg.Output)
	if err != nil {
		return err
	}

	if err := reporter.Report(os.Stdout, result); err != nil {
		return fmt.Errorf("report error: %w", err)
	}

	if shouldFail(cfg.FailOn, &result.Summary) {
		return ErrFindingsExceedThreshold
	}

	if code := severityExitCode(&result.Summary); code > 0 {
		return &SeverityExitError{Code: code, Message: fmt.Sprintf("findings detected (exit %d)", code)}
	}

	return nil
}

func severityExitCode(s *types.Summary) int {
	if s.Critical > 0 {
		return 10
	}
	if s.High > 0 {
		return 11
	}
	if s.Medium > 0 {
		return 12
	}
	return 0
}

func shouldFail(failOn []types.Severity, summary *types.Summary) bool {
	if len(failOn) == 0 {
		return false
	}
	return summary.HasSeverity(failOn...)
}

func filterNewFindings(current []types.Finding, baselinePath string) ([]types.Finding, error) {
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read baseline: %w", err)
	}
	var baseline types.ScanResult
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("invalid baseline JSON: %w", err)
	}

	known := make(map[string]bool, len(baseline.Findings))
	for i := range baseline.Findings {
		fp := baseline.Findings[i].Fingerprint
		if fp == "" {
			fp = baseline.Findings[i].ComputeFingerprint()
		}
		known[fp] = true
	}

	var newFindings []types.Finding
	for _, f := range current {
		if !known[f.Fingerprint] {
			newFindings = append(newFindings, f)
		}
	}
	return newFindings, nil
}
