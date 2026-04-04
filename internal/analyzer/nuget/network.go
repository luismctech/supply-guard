package nuget

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkNuGetNetworkCalls(dir string) []types.Finding {
	var findings []types.Finding

	skipDirs := []string{".git", "node_modules", "bin", "obj"}
	_ = safefile.WalkDir(dir, skipDirs, func(path string, d os.DirEntry) error {
		name := d.Name()
		if !strings.HasSuffix(name, ".targets") && !strings.HasSuffix(name, ".props") {
			return nil
		}

		data, readErr := safefile.ReadFile(path)
		if readErr != nil {
			return nil
		}

		content := string(data)
		issues := check.ScanForNetworkCalls(content, "nuget")

		relPath, _ := filepath.Rel(dir, path)
		if relPath == "" {
			relPath = path
		}

		for _, issue := range issues {
			if issue.Category == "c2_domain" || issue.Category == "raw_ip" || issue.Category == "download_cmd" || issue.Category == "network_api" {
				sev := types.SeverityHigh
				if issue.Risk == "critical" {
					sev = types.SeverityCritical
				}
				findings = append(findings, types.Finding{
					CheckID:     types.CheckNetworkCalls,
					Severity:    sev,
					Ecosystem:   "nuget",
					File:        relPath,
					Title:       "Network pattern in build file: " + issue.Pattern,
					Description: relPath + " contains a " + issue.Category + " pattern (" + issue.Pattern + ") that may indicate download or exfiltration during build.",
					Remediation: "Review " + relPath + " and ensure no unauthorized network access occurs during build.",
				})
			}
		}

		return nil
	})

	return findings
}
