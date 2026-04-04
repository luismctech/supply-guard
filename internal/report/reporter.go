package report

import (
	"fmt"
	"io"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type Reporter interface {
	Report(w io.Writer, result *types.ScanResult) error
}

func Get(format string) (Reporter, error) {
	switch format {
	case "table":
		return &TableReporter{}, nil
	case "json":
		return &JSONReporter{}, nil
	case "sarif":
		return &SARIFReporter{}, nil
	case "markdown", "md":
		return &MarkdownReporter{}, nil
	case "diff":
		return &DiffReporter{}, nil
	case "stream-json":
		return &StreamReporter{}, nil
	default:
		return nil, fmt.Errorf("unknown output format: %s (use table, json, sarif, markdown, diff, or stream-json)", format)
	}
}
