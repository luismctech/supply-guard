package pip

import (
	"path/filepath"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkPipNetworkCalls(dir string) []types.Finding {
	var findings []types.Finding

	targets := []string{"setup.py", "setup.cfg", "conftest.py"}

	for _, target := range targets {
		path := filepath.Join(dir, target)
		data, err := safefile.ReadFile(path)
		if err != nil {
			continue
		}

		content := string(data)
		issues := check.ScanForNetworkCalls(content, "pip")
		for _, issue := range issues {
			sev := types.SeverityHigh
			if issue.Risk == "critical" {
				sev = types.SeverityCritical
			}
			findings = append(findings, types.Finding{
				CheckID:     types.CheckNetworkCalls,
				Severity:    sev,
				Ecosystem:   "pip",
				File:        target,
				Title:       "Network/exec pattern in " + target + ": " + issue.Pattern,
				Description: target + " contains a " + issue.Category + " pattern (" + issue.Pattern + ") that may indicate data exfiltration or remote code execution during install.",
				Remediation: "Review " + target + " and remove any network calls that are not essential for package setup.",
			})
		}
	}

	return findings
}
