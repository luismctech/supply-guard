package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

var reportCmd = &cobra.Command{
	Use:   "report [scan-result.json]",
	Short: "Generate formatted reports from scan results",
	Long: `Generate different report formats from a saved JSON scan result.

Formats:
  pr-comment        GitHub PR comment with collapsible findings
  executive-summary High-level overview for stakeholders
  commit-message    Git commit message summarizing fixes
  developer-brief   Concise developer-focused action items`,
	Args:          cobra.ExactArgs(1),
	RunE:          runReport,
	SilenceErrors: true,
	SilenceUsage:  true,
}

var reportFormat string

func init() {
	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "pr-comment", "report format: pr-comment, executive-summary, commit-message, developer-brief")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("cannot read scan result: %w", err)
	}

	var result types.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("invalid scan result JSON: %w", err)
	}

	switch reportFormat {
	case "pr-comment":
		return writePRComment(os.Stdout, &result)
	case "executive-summary":
		return writeExecutiveSummary(os.Stdout, &result)
	case "commit-message":
		return writeCommitMessage(os.Stdout, &result)
	case "developer-brief":
		return writeDeveloperBrief(os.Stdout, &result)
	default:
		return fmt.Errorf("unknown report format: %s (use pr-comment, executive-summary, commit-message, or developer-brief)", reportFormat)
	}
}

func writePRComment(w *os.File, r *types.ScanResult) error {
	fmt.Fprintf(w, "## SupplyGuard Security Scan\n\n")

	if r.Summary.Total == 0 {
		fmt.Fprintf(w, "**No supply chain security issues found.**\n")
		return nil
	}

	fmt.Fprintf(w, "| Severity | Count |\n|---|---:|\n")
	if r.Summary.Critical > 0 {
		fmt.Fprintf(w, "| :red_circle: Critical | %d |\n", r.Summary.Critical)
	}
	if r.Summary.High > 0 {
		fmt.Fprintf(w, "| :orange_circle: High | %d |\n", r.Summary.High)
	}
	if r.Summary.Medium > 0 {
		fmt.Fprintf(w, "| :yellow_circle: Medium | %d |\n", r.Summary.Medium)
	}
	if r.Summary.Low > 0 {
		fmt.Fprintf(w, "| :blue_circle: Low | %d |\n", r.Summary.Low)
	}
	if r.Summary.Info > 0 {
		fmt.Fprintf(w, "| :white_circle: Info | %d |\n", r.Summary.Info)
	}
	fmt.Fprintf(w, "\n")

	grouped := groupBySeverity(r.Findings)
	for _, sev := range []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow, types.SeverityInfo} {
		findings := grouped[sev]
		if len(findings) == 0 {
			continue
		}
		fmt.Fprintf(w, "<details>\n<summary><strong>%s (%d)</strong></summary>\n\n", strings.ToUpper(string(sev)), len(findings))
		for _, f := range findings {
			fmt.Fprintf(w, "- **`[%s]`** %s", f.CheckID, f.Title)
			if f.File != "" {
				fmt.Fprintf(w, " — `%s`", f.File)
				if f.Line > 0 {
					fmt.Fprintf(w, ":%d", f.Line)
				}
			}
			fmt.Fprintf(w, "\n")
			if f.Remediation != "" {
				fmt.Fprintf(w, "  > %s\n", f.Remediation)
			}
		}
		fmt.Fprintf(w, "\n</details>\n\n")
	}

	return nil
}

func writeExecutiveSummary(w *os.File, r *types.ScanResult) error {
	fmt.Fprintf(w, "# Supply Chain Security Summary\n\n")
	fmt.Fprintf(w, "**Project:** %s\n", r.ProjectDir)
	fmt.Fprintf(w, "**Scan date:** %s\n", r.Timestamp.Format("2006-01-02"))
	fmt.Fprintf(w, "**Ecosystems:** %s\n\n", strings.Join(r.Ecosystems, ", "))

	if r.Summary.Total == 0 {
		fmt.Fprintf(w, "## Status: PASS\n\nNo supply chain security issues were detected.\n")
		return nil
	}

	status := "PASS"
	if r.Summary.Critical > 0 || r.Summary.High > 0 {
		status = "FAIL"
	} else if r.Summary.Medium > 0 {
		status = "WARNING"
	}
	fmt.Fprintf(w, "## Status: %s\n\n", status)
	fmt.Fprintf(w, "**Total findings:** %d\n\n", r.Summary.Total)

	if r.Summary.Critical > 0 {
		fmt.Fprintf(w, "- **%d critical** issues require immediate attention\n", r.Summary.Critical)
	}
	if r.Summary.High > 0 {
		fmt.Fprintf(w, "- **%d high** severity issues should be resolved before merge\n", r.Summary.High)
	}
	if r.Summary.Medium > 0 {
		fmt.Fprintf(w, "- **%d medium** issues should be addressed in the next sprint\n", r.Summary.Medium)
	}
	if r.Summary.Low+r.Summary.Info > 0 {
		fmt.Fprintf(w, "- **%d** informational/low items for awareness\n", r.Summary.Low+r.Summary.Info)
	}

	fmt.Fprintf(w, "\n## Top Risks\n\n")
	count := 0
	for _, f := range r.Findings {
		if count >= 5 {
			break
		}
		if f.Severity == types.SeverityCritical || f.Severity == types.SeverityHigh {
			fmt.Fprintf(w, "- [%s] %s — %s\n", f.CheckID, f.Title, f.Description)
			count++
		}
	}

	return nil
}

func writeCommitMessage(w *os.File, r *types.ScanResult) error {
	if r.Summary.Total == 0 {
		fmt.Fprintf(w, "security: clean supply chain scan (no findings)\n")
		return nil
	}

	parts := []string{}
	if r.Summary.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", r.Summary.Critical))
	}
	if r.Summary.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", r.Summary.High))
	}
	if r.Summary.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", r.Summary.Medium))
	}

	fmt.Fprintf(w, "security: fix %s supply chain findings\n\n", strings.Join(parts, ", "))

	checks := map[types.CheckID]int{}
	for _, f := range r.Findings {
		if f.Severity == types.SeverityCritical || f.Severity == types.SeverityHigh || f.Severity == types.SeverityMedium {
			checks[f.CheckID]++
		}
	}
	for id, count := range checks {
		desc := types.CheckDescriptions[id]
		fmt.Fprintf(w, "- %s: %s (%d)\n", id, desc, count)
	}

	return nil
}

func writeDeveloperBrief(w *os.File, r *types.ScanResult) error {
	fmt.Fprintf(w, "# Action Items\n\n")

	if r.Summary.Total == 0 {
		fmt.Fprintf(w, "No action items. Supply chain scan is clean.\n")
		return nil
	}

	for i, f := range r.Findings {
		if f.Severity == types.SeverityInfo {
			continue
		}
		fmt.Fprintf(w, "%d. **[%s] %s** `%s`", i+1, f.Severity, f.Title, f.File)
		if f.Line > 0 {
			fmt.Fprintf(w, ":%d", f.Line)
		}
		fmt.Fprintf(w, "\n")
		if f.Remediation != "" {
			fmt.Fprintf(w, "   - Fix: %s\n", f.Remediation)
		}
		if f.Fix != nil && f.Fix.Description != "" {
			fmt.Fprintf(w, "   - Suggestion: %s\n", f.Fix.Description)
		}
		fmt.Fprintf(w, "\n")
	}

	return nil
}

func groupBySeverity(findings []types.Finding) map[types.Severity][]types.Finding {
	groups := make(map[types.Severity][]types.Finding)
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}
	return groups
}
