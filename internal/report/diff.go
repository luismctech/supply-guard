package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type DiffReporter struct{}

func (r *DiffReporter) Report(w io.Writer, result *types.ScanResult) error {
	patchCount := 0
	for _, f := range result.Findings {
		if f.Fix == nil {
			continue
		}
		if f.Fix.Type == "replace" && f.Fix.OldContent != "" && f.Fix.NewContent != "" {
			r.writeReplacePatch(w, &f)
			patchCount++
		} else if f.Fix.Type == "add" && f.Fix.NewContent != "" {
			r.writeAddPatch(w, &f)
			patchCount++
		} else if f.Fix.Type == "delete" && f.Fix.OldContent != "" {
			r.writeDeletePatch(w, &f)
			patchCount++
		}
	}
	if patchCount == 0 {
		fmt.Fprintf(w, "# No auto-fixable findings.\n")
		fmt.Fprintf(w, "# Total findings: %d (use --output json for details)\n", result.Summary.Total)
	}
	return nil
}

func (r *DiffReporter) writeReplacePatch(w io.Writer, f *types.Finding) {
	file := f.Fix.File
	if file == "" {
		file = f.File
	}
	oldLines := strings.Split(f.Fix.OldContent, "\n")
	newLines := strings.Split(f.Fix.NewContent, "\n")
	line := f.Fix.Line
	if line == 0 {
		line = f.Line
	}
	if line == 0 {
		line = 1
	}

	fmt.Fprintf(w, "--- a/%s\n", file)
	fmt.Fprintf(w, "+++ b/%s\n", file)
	fmt.Fprintf(w, "@@ -%d,%d +%d,%d @@ %s [%s]\n",
		line, len(oldLines), line, len(newLines),
		sanitize(f.Title), f.CheckID)
	for _, l := range oldLines {
		fmt.Fprintf(w, "-%s\n", l)
	}
	for _, l := range newLines {
		fmt.Fprintf(w, "+%s\n", l)
	}
}

func (r *DiffReporter) writeAddPatch(w io.Writer, f *types.Finding) {
	file := f.Fix.File
	if file == "" {
		file = f.File
	}
	newLines := strings.Split(f.Fix.NewContent, "\n")
	line := f.Fix.Line
	if line == 0 {
		line = f.Line
	}
	if line == 0 {
		line = 1
	}

	fmt.Fprintf(w, "--- a/%s\n", file)
	fmt.Fprintf(w, "+++ b/%s\n", file)
	fmt.Fprintf(w, "@@ -%d,0 +%d,%d @@ %s [%s]\n",
		line, line, len(newLines),
		sanitize(f.Title), f.CheckID)
	for _, l := range newLines {
		fmt.Fprintf(w, "+%s\n", l)
	}
}

func (r *DiffReporter) writeDeletePatch(w io.Writer, f *types.Finding) {
	file := f.Fix.File
	if file == "" {
		file = f.File
	}
	oldLines := strings.Split(f.Fix.OldContent, "\n")
	line := f.Fix.Line
	if line == 0 {
		line = f.Line
	}
	if line == 0 {
		line = 1
	}

	fmt.Fprintf(w, "--- a/%s\n", file)
	fmt.Fprintf(w, "+++ b/%s\n", file)
	fmt.Fprintf(w, "@@ -%d,%d +%d,0 @@ %s [%s]\n",
		line, len(oldLines), line,
		sanitize(f.Title), f.CheckID)
	for _, l := range oldLines {
		fmt.Fprintf(w, "-%s\n", l)
	}
}
