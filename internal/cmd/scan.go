package cmd

import (
	"context"
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

func init() {
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}

	linfo, err := os.Lstat(absDir)
	if err != nil {
		return fmt.Errorf("not a valid directory: %s", absDir)
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintf(os.Stderr, "⚠  Warning: scan target %s is a symlink. Resolving to real path.\n", absDir)
		absDir, err = filepath.EvalSymlinks(absDir)
		if err != nil {
			return fmt.Errorf("cannot resolve symlink: %w", err)
		}
	}
	info, err := os.Stat(absDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("not a valid directory: %s", absDir)
	}

	WarnIfUntrustedConfig(absDir)

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	eng := engine.New(cfg)
	result, err := eng.Scan(context.Background(), absDir)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
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

	return nil
}

func shouldFail(failOn []types.Severity, summary *types.Summary) bool {
	if len(failOn) == 0 {
		return false
	}
	return summary.HasSeverity(failOn...)
}
