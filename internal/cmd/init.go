package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/AlbertoMZCruz/supply-guard/internal/ui"
)

var initCmd = &cobra.Command{
	Use:   "init [directory]",
	Short: "Initialize supply-guard in a project",
	Long: `Creates security-hardening configuration files:
  - supplyguard.yaml (scanner configuration)
  - .npmrc with ignore-scripts=true`,
	Args: cobra.MaximumNArgs(1),
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}

	if err := os.MkdirAll(absDir, 0755); err != nil {
		return fmt.Errorf("cannot create directory: %w", err)
	}

	cfgPath := filepath.Join(absDir, "supplyguard.yaml")
	created, err := writeIfNotExists(cfgPath, configTemplate)
	if err != nil {
		return fmt.Errorf("creating config: %w", err)
	}
	if created {
		fmt.Printf("  %s Created %s\n", ui.Success("✓"), cfgPath)
	} else {
		fmt.Printf("  %s Skipped %s %s\n", ui.Dim("○"), cfgPath, ui.Dim("(already exists)"))
	}

	npmrcPath := filepath.Join(absDir, ".npmrc")
	added, err := appendIfMissing(npmrcPath, "ignore-scripts=true")
	if err != nil {
		fmt.Printf("  %s Could not update .npmrc: %v\n", ui.Warn("⚠"), err)
	} else if added {
		fmt.Printf("  %s Hardened %s %s\n", ui.Success("✓"), npmrcPath, ui.Dim("(ignore-scripts=true)"))
	} else {
		fmt.Printf("  %s Skipped %s %s\n", ui.Dim("○"), npmrcPath, ui.Dim("(ignore-scripts=true already set)"))
	}

	fmt.Printf("\n  %s Run %s to scan your project.\n\n", ui.BoldGreen("SupplyGuard initialized."), ui.Bold("supply-guard scan"))
	return nil
}

// writeIfNotExists creates a file only if it doesn't already exist.
// Returns (true, nil) if created, (false, nil) if already exists.
func writeIfNotExists(path, content string) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err == nil, err
}

// appendIfMissing appends a line to a file if it's not already present.
// Returns (true, nil) if appended, (false, nil) if already present.
func appendIfMissing(path, line string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, os.WriteFile(path, []byte(line+"\n"), 0644)
		}
		return false, err
	}

	for _, l := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) == line {
			return false, nil
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.WriteString("\n" + line + "\n")
	return err == nil, err
}

const configTemplate = `# SupplyGuard configuration
# Docs: https://github.com/AlbertoMZCruz/supply-guard

# Output format: table, json, sarif
output: table

# Fail CI when findings match these severities
# fail_on:
#   - critical
#   - high

# Ecosystems to scan (auto-detected if enabled)
ecosystems:
  npm:
    enabled: true
  pip:
    enabled: true
  cargo:
    enabled: true
  nuget:
    enabled: true
  maven:
    enabled: true
  gradle:
    enabled: true

# Check-specific configuration
checks:
  dependency_age_days: 7
  version_range_strictness: conservative
  # Disable checks by ID: SG001-SG012
  # disabled:
  #   - SG005

# Ignore packages entirely (all checks)
# ignore:
#   - some-trusted-package

# Granular ignore rules (all non-empty fields must match)
# ignore_rules:
#   - check: SG002
#     package: esbuild
#     reason: "trusted build tool"
#   - check: SG009
#     file: ".github/workflows/*.yml"
#     reason: "managed by Renovate"
`
