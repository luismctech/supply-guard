package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type packageWithScripts struct {
	Name    string            `json:"name"`
	Scripts map[string]string `json:"scripts"`
}

var dangerousScripts = []string{"preinstall", "install", "postinstall", "preuninstall", "postuninstall"}

func checkInstallScripts(pf *projectFiles) []types.Finding {
	var findings []types.Finding

	if pf.pkg == nil {
		return findings
	}

	for _, scriptName := range dangerousScripts {
		script, ok := pf.pkg.Scripts[scriptName]
		if !ok {
			continue
		}

		findings = append(findings, types.Finding{
			CheckID:     types.CheckInstallScripts,
			Severity:    types.SeverityMedium,
			Ecosystem:   "npm",
			Package:     pf.pkg.Name,
			File:        "package.json",
			Title:       "Lifecycle script detected: " + scriptName,
			Description: "Package defines a '" + scriptName + "' lifecycle script. These scripts execute automatically during npm install and are the primary attack vector for npm supply chain attacks.",
			Remediation: "Review the script content. Add 'ignore-scripts=true' to .npmrc to prevent automatic execution.",
		})

		netIssues := check.ScanForNetworkCalls(script, "npm")
		for _, issue := range netIssues {
			sev := types.SeverityHigh
			if issue.Risk == "critical" {
				sev = types.SeverityCritical
			}
			findings = append(findings, types.Finding{
				CheckID:   types.CheckNetworkCalls,
				Severity:  sev,
				Ecosystem: "npm",
				Package:   pf.pkg.Name,
				File:      "package.json",
				Title:     "Network/exec pattern in lifecycle script '" + scriptName + "': " + issue.Pattern,
				Description: "The '" + scriptName + "' script contains a " + issue.Category +
					" pattern (" + issue.Pattern + ") that may indicate data exfiltration or remote code execution.",
				Remediation: "Review the script content carefully. Remove network calls from lifecycle scripts.",
			})
		}
	}

	findings = append(findings, scanNodeModulesScripts(pf.dir)...)

	return findings
}

func scanNodeModulesScripts(dir string) []types.Finding {
	var findings []types.Finding

	nodeModules := filepath.Join(dir, "node_modules")
	if _, err := os.Stat(nodeModules); err != nil {
		return findings
	}

	entries, err := os.ReadDir(nodeModules)
	if err != nil {
		return findings
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}

		// Handle scoped packages
		if strings.HasPrefix(name, "@") {
			scopeEntries, err := os.ReadDir(filepath.Join(nodeModules, name))
			if err != nil {
				continue
			}
			for _, scopeEntry := range scopeEntries {
				if !scopeEntry.IsDir() {
					continue
				}
				pkgName := name + "/" + scopeEntry.Name()
				pkgFindings := checkModulePackageScripts(dir, nodeModules, pkgName)
				findings = append(findings, pkgFindings...)
			}
			continue
		}

		pkgFindings := checkModulePackageScripts(dir, nodeModules, name)
		findings = append(findings, pkgFindings...)
	}

	return findings
}

func checkModulePackageScripts(projectDir, nodeModules, pkgName string) []types.Finding {
	var findings []types.Finding

	pkgJSONPath := filepath.Join(nodeModules, pkgName, "package.json")
	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return findings
	}

	var pkg packageWithScripts
	if err := json.Unmarshal(data, &pkg); err != nil {
		return findings
	}

	for _, scriptName := range dangerousScripts {
		script, ok := pkg.Scripts[scriptName]
		if !ok {
			continue
		}

		relPath, _ := filepath.Rel(projectDir, pkgJSONPath)
		if relPath == "" {
			relPath = pkgJSONPath
		}

		findings = append(findings, types.Finding{
			CheckID:     types.CheckInstallScripts,
			Severity:    types.SeverityMedium,
			Ecosystem:   "npm",
			Package:     pkgName,
			File:        relPath,
			Title:       "Dependency has lifecycle script: " + scriptName,
			Description: "Dependency '" + pkgName + "' defines a '" + scriptName + "' script: " + truncate(script, 200),
			Remediation: "Review the script. If trusted, add to allowlist. Otherwise, find an alternative package.",
		})

		netIssues := check.ScanForNetworkCalls(script, "npm")
		for _, issue := range netIssues {
			sev := types.SeverityHigh
			if issue.Risk == "critical" {
				sev = types.SeverityCritical
			}
			findings = append(findings, types.Finding{
				CheckID:   types.CheckNetworkCalls,
				Severity:  sev,
				Ecosystem: "npm",
				Package:   pkgName,
				File:      relPath,
				Title:     "Network/exec pattern in dependency script '" + scriptName + "': " + issue.Pattern,
				Description: "Dependency '" + pkgName + "' script contains a " + issue.Category +
					" pattern (" + issue.Pattern + ") that may indicate data exfiltration or remote code execution.",
				Remediation: "Review the dependency script. Consider replacing with an alternative package.",
			})
		}
	}

	return findings
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
