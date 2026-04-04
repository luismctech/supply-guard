package maven

import (
	"os"
	"path/filepath"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkMavenNetworkCalls(dir string) []types.Finding {
	var findings []types.Finding

	targets := map[string]string{
		"pom.xml": "maven",
	}

	for _, buildFile := range []string{"build.gradle", "build.gradle.kts"} {
		if _, err := os.Stat(filepath.Join(dir, buildFile)); err == nil {
			targets[buildFile] = "maven"
		}
	}

	for file, eco := range targets {
		path := filepath.Join(dir, file)
		data, err := safefile.ReadFile(path)
		if err != nil {
			continue
		}

		content := string(data)
		issues := check.ScanForNetworkCalls(content, eco)
		for _, issue := range issues {
			if issue.Category == "c2_domain" || issue.Category == "raw_ip" || issue.Category == "download_cmd" {
				sev := types.SeverityHigh
				if issue.Risk == "critical" {
					sev = types.SeverityCritical
				}
				findings = append(findings, types.Finding{
					CheckID:     types.CheckNetworkCalls,
					Severity:    sev,
					Ecosystem:   eco,
					File:        file,
					Title:       "Network pattern in build file: " + issue.Pattern,
					Description: file + " contains a " + issue.Category + " pattern (" + issue.Pattern + ") that may indicate data exfiltration.",
					Remediation: "Review " + file + " and remove suspicious network references.",
				})
			}
		}
	}

	return findings
}
