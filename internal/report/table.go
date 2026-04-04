package report

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

type TableReporter struct{}

func (r *TableReporter) Report(w io.Writer, result *types.ScanResult) error {
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  SupplyGuard Scan Results\n")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 60))
	fmt.Fprintf(w, "  Project:     %s\n", result.ProjectDir)
	fmt.Fprintf(w, "  Ecosystems:  %s\n", strings.Join(result.Ecosystems, ", "))
	fmt.Fprintf(w, "  Duration:    %s\n", result.Duration)
	fmt.Fprintf(w, "  %s\n\n", strings.Repeat("─", 60))

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "  ✓ No issues found\n\n")
		return nil
	}

	for i, f := range result.Findings {
		icon := severityIcon(f.Severity)
		fmt.Fprintf(w, "  %s [%s] %s\n", icon, f.CheckID, sanitize(f.Title))
		fmt.Fprintf(w, "    Severity:  %s\n", strings.ToUpper(string(f.Severity)))
		if f.Package != "" {
			pkg := sanitize(f.Package)
			if f.Version != "" {
				pkg += "@" + sanitize(f.Version)
			}
			fmt.Fprintf(w, "    Package:   %s\n", pkg)
		}
		fmt.Fprintf(w, "    File:      %s", sanitize(f.File))
		if f.Line > 0 {
			fmt.Fprintf(w, ":%d", f.Line)
		}
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "    %s\n", sanitize(f.Description))
		if f.Remediation != "" {
			fmt.Fprintf(w, "    Fix:       %s\n", sanitize(f.Remediation))
		}
		if i < len(result.Findings)-1 {
			fmt.Fprintf(w, "\n")
		}
	}

	fmt.Fprintf(w, "\n  %s\n", strings.Repeat("─", 60))
	fmt.Fprintf(w, "  Summary: %d findings", result.Summary.Total)

	parts := []string{}
	if result.Summary.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", result.Summary.Critical))
	}
	if result.Summary.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", result.Summary.High))
	}
	if result.Summary.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", result.Summary.Medium))
	}
	if result.Summary.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", result.Summary.Low))
	}
	if result.Summary.Info > 0 {
		parts = append(parts, fmt.Sprintf("%d info", result.Summary.Info))
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintf(w, "\n\n")

	return nil
}

func severityIcon(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return "✖"
	case types.SeverityHigh:
		return "✖"
	case types.SeverityMedium:
		return "▲"
	case types.SeverityLow:
		return "●"
	case types.SeverityInfo:
		return "○"
	default:
		return "?"
	}
}
