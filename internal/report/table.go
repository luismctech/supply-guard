package report

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
	"github.com/AlbertoMZCruz/supply-guard/internal/ui"
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
	rule := ui.Dim(strings.Repeat("─", 62))

	writeHeader(w, rule, result)

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "  %s %s\n\n", ui.Success("✓"), ui.BoldGreen("No issues found"))
		return nil
	}

	for i, f := range result.Findings {
		writeFinding(w, &f)
		if i < len(result.Findings)-1 {
			fmt.Fprintf(w, "\n")
		}
	}

	writeFooter(w, rule, &result.Summary)
	return nil
}

func writeHeader(w io.Writer, rule string, result *types.ScanResult) {
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  %s\n", ui.Bold("🛡  SupplyGuard"))
	fmt.Fprintf(w, "  %s\n", rule)

	field(w, "Project", result.ProjectDir)
	field(w, "Ecosystems", strings.Join(result.Ecosystems, ", "))
	field(w, "Duration", result.Duration)

	fmt.Fprintf(w, "  %s\n\n", rule)
}

func writeFinding(w io.Writer, f *types.Finding) {
	icon := severityIcon(f.Severity)
	fmt.Fprintf(w, "  %s %s %s\n", icon, ui.Bold(fmt.Sprintf("[%s]", f.CheckID)), sanitize(f.Title))

	field(w, "  Severity", severityLabel(f.Severity))

	if f.Package != "" {
		pkg := sanitize(f.Package)
		if f.Version != "" {
			pkg += ui.Dim("@") + sanitize(f.Version)
		}
		field(w, "  Package", ui.Bold(pkg))
	}

	fileLoc := ui.Cyan(sanitize(f.File))
	if f.Line > 0 {
		fileLoc += ui.Dim(fmt.Sprintf(":%d", f.Line))
	}
	field(w, "  File", fileLoc)

	fmt.Fprintf(w, "    %s\n", ui.Dim(sanitize(f.Description)))

	if f.Remediation != "" {
		field(w, "  Fix", ui.Green(sanitize(f.Remediation)))
	}
}

func writeFooter(w io.Writer, rule string, s *types.Summary) {
	fmt.Fprintf(w, "\n  %s\n", rule)

	parts := []string{ui.Bold(fmt.Sprintf("%d findings", s.Total))}
	if s.Critical > 0 {
		parts = append(parts, ui.Critical(fmt.Sprintf("■ %d critical", s.Critical)))
	}
	if s.High > 0 {
		parts = append(parts, ui.High(fmt.Sprintf("■ %d high", s.High)))
	}
	if s.Medium > 0 {
		parts = append(parts, ui.Medium(fmt.Sprintf("■ %d medium", s.Medium)))
	}
	if s.Low > 0 {
		parts = append(parts, ui.Low(fmt.Sprintf("■ %d low", s.Low)))
	}
	if s.Info > 0 {
		parts = append(parts, ui.Info(fmt.Sprintf("■ %d info", s.Info)))
	}
	fmt.Fprintf(w, "  %s\n\n", strings.Join(parts, "  "))
}

func field(w io.Writer, label, value string) {
	fmt.Fprintf(w, "  %s  %s\n", ui.Dim(label), value)
}

func severityIcon(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return ui.Critical("✖")
	case types.SeverityHigh:
		return ui.High("✖")
	case types.SeverityMedium:
		return ui.Medium("▲")
	case types.SeverityLow:
		return ui.Low("●")
	case types.SeverityInfo:
		return ui.Info("○")
	default:
		return "?"
	}
}

func severityLabel(s types.Severity) string {
	upper := strings.ToUpper(string(s))
	switch s {
	case types.SeverityCritical:
		return ui.Critical(upper)
	case types.SeverityHigh:
		return ui.High(upper)
	case types.SeverityMedium:
		return ui.Medium(upper)
	case types.SeverityLow:
		return ui.Low(upper)
	case types.SeverityInfo:
		return ui.Info(upper)
	default:
		return upper
	}
}
