package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type MarkdownReporter struct{}

func (r *MarkdownReporter) Report(w io.Writer, result *types.ScanResult) error {
	fmt.Fprintf(w, "# SupplyGuard Scan Report\n\n")
	fmt.Fprintf(w, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Project | `%s` |\n", sanitize(result.ProjectDir))
	fmt.Fprintf(w, "| Ecosystems | %s |\n", strings.Join(result.Ecosystems, ", "))
	fmt.Fprintf(w, "| Duration | %s |\n", result.Duration)
	fmt.Fprintf(w, "| Scanned at | %s |\n\n", result.Timestamp.Format("2006-01-02 15:04:05 UTC"))

	r.writeSummaryTable(w, &result.Summary)

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "**No issues found.**\n")
		return nil
	}

	fmt.Fprintf(w, "## Findings\n\n")
	for _, f := range result.Findings {
		r.writeFinding(w, &f)
	}

	return nil
}

func (r *MarkdownReporter) writeSummaryTable(w io.Writer, s *types.Summary) {
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Severity | Count |\n|---|---:|\n")
	if s.Critical > 0 {
		fmt.Fprintf(w, "| **CRITICAL** | %d |\n", s.Critical)
	}
	if s.High > 0 {
		fmt.Fprintf(w, "| **HIGH** | %d |\n", s.High)
	}
	if s.Medium > 0 {
		fmt.Fprintf(w, "| MEDIUM | %d |\n", s.Medium)
	}
	if s.Low > 0 {
		fmt.Fprintf(w, "| LOW | %d |\n", s.Low)
	}
	if s.Info > 0 {
		fmt.Fprintf(w, "| INFO | %d |\n", s.Info)
	}
	fmt.Fprintf(w, "| **Total** | **%d** |\n\n", s.Total)
}

func (r *MarkdownReporter) writeFinding(w io.Writer, f *types.Finding) {
	badge := severityBadge(f.Severity)
	fmt.Fprintf(w, "### %s `[%s]` %s\n\n", badge, f.CheckID, sanitize(f.Title))

	if f.Package != "" {
		pkg := sanitize(f.Package)
		if f.Version != "" {
			pkg += "@" + sanitize(f.Version)
		}
		fmt.Fprintf(w, "- **Package:** `%s`\n", pkg)
	}

	loc := sanitize(f.File)
	if f.Line > 0 {
		loc += fmt.Sprintf(":%d", f.Line)
	}
	fmt.Fprintf(w, "- **Location:** `%s`\n", loc)
	fmt.Fprintf(w, "- **Ecosystem:** %s\n\n", f.Ecosystem)
	fmt.Fprintf(w, "%s\n\n", sanitize(f.Description))

	if f.Remediation != "" {
		fmt.Fprintf(w, "> **Remediation:** %s\n\n", sanitize(f.Remediation))
	}

	if f.Fix != nil {
		r.writeFixSuggestion(w, f.Fix)
	}

	fmt.Fprintf(w, "---\n\n")
}

func (r *MarkdownReporter) writeFixSuggestion(w io.Writer, fix *types.FixSuggestion) {
	fmt.Fprintf(w, "<details>\n<summary>Suggested fix</summary>\n\n")
	if fix.Description != "" {
		fmt.Fprintf(w, "%s\n\n", fix.Description)
	}
	if fix.OldContent != "" && fix.NewContent != "" {
		fmt.Fprintf(w, "**Replace** in `%s`", fix.File)
		if fix.Line > 0 {
			fmt.Fprintf(w, ":%d", fix.Line)
		}
		fmt.Fprintf(w, ":\n\n```diff\n- %s\n+ %s\n```\n\n",
			strings.ReplaceAll(fix.OldContent, "\n", "\n- "),
			strings.ReplaceAll(fix.NewContent, "\n", "\n+ "))
	} else if fix.NewContent != "" {
		fmt.Fprintf(w, "**Add** to `%s`:\n\n```\n%s\n```\n\n", fix.File, fix.NewContent)
	}
	fmt.Fprintf(w, "</details>\n\n")
}

func severityBadge(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return "🔴"
	case types.SeverityHigh:
		return "🟠"
	case types.SeverityMedium:
		return "🟡"
	case types.SeverityLow:
		return "🔵"
	case types.SeverityInfo:
		return "⚪"
	default:
		return "⚪"
	}
}
