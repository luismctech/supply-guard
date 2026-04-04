package check

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
)

type ProvenanceIssue struct {
	Package     string
	File        string
	IssueType   string // "missing_integrity", "git_source", "no_slsa_workflow"
	Description string
}

// CheckNpmIntegrity scans package-lock.json for packages missing SRI integrity hashes.
func CheckNpmIntegrity(dir string) []ProvenanceIssue {
	lockPath := filepath.Join(dir, "package-lock.json")
	data, err := safefile.ReadFile(lockPath)
	if err != nil {
		return nil
	}

	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}

	var issues []ProvenanceIssue

	if lock.LockfileVersion >= 2 {
		for key, pkg := range lock.Packages {
			if key == "" {
				continue
			}
			name := key
			if strings.HasPrefix(key, "node_modules/") {
				name = key[len("node_modules/"):]
			}
			if pkg.Integrity == "" && pkg.Resolved != "" {
				if isGitOrURLSource(pkg.Resolved) {
					issues = append(issues, ProvenanceIssue{
						Package:     name,
						File:        "package-lock.json",
						IssueType:   "git_source",
						Description: "Package '" + name + "' resolved from a non-registry source (" + truncateStr(pkg.Resolved, 80) + "). Registry provenance is not available.",
					})
				} else {
					issues = append(issues, ProvenanceIssue{
						Package:     name,
						File:        "package-lock.json",
						IssueType:   "missing_integrity",
						Description: "Package '" + name + "' is missing an SRI integrity hash. It cannot be verified against tampering.",
					})
				}
			}
		}
		return issues
	}

	for name, dep := range lock.Dependencies {
		if dep.Integrity == "" && dep.Resolved != "" {
			if isGitOrURLSource(dep.Resolved) {
				issues = append(issues, ProvenanceIssue{
					Package:     name,
					File:        "package-lock.json",
					IssueType:   "git_source",
					Description: "Package '" + name + "' resolved from a non-registry source. Registry provenance is not available.",
				})
			} else {
				issues = append(issues, ProvenanceIssue{
					Package:     name,
					File:        "package-lock.json",
					IssueType:   "missing_integrity",
					Description: "Package '" + name + "' is missing an SRI integrity hash.",
				})
			}
		}
	}

	return issues
}

// CheckPipHashes scans requirements files for missing --hash entries.
func CheckPipHashes(dir string) []ProvenanceIssue {
	var issues []ProvenanceIssue

	reqFiles := []string{"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}
	for _, reqFile := range reqFiles {
		path := filepath.Join(dir, reqFile)
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := safefile.NewScanner(f)
		hasAnyHash := false
		var unhashed []string
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
				if strings.Contains(line, "--require-hashes") {
					hasAnyHash = true
				}
				continue
			}
			if strings.Contains(line, "--hash=") || strings.Contains(line, "--hash ") {
				hasAnyHash = true
			} else if !strings.HasPrefix(line, "-") {
				parts := strings.FieldsFunc(line, func(r rune) bool {
					return r == '=' || r == '>' || r == '<' || r == '!' || r == '~'
				})
				if len(parts) > 0 {
					unhashed = append(unhashed, strings.TrimSpace(parts[0]))
				}
			}
		}
		f.Close()

		if hasAnyHash && len(unhashed) > 0 {
			for _, pkg := range unhashed {
				issues = append(issues, ProvenanceIssue{
					Package:     pkg,
					File:        reqFile,
					IssueType:   "missing_integrity",
					Description: "Package '" + pkg + "' is missing a --hash entry in " + reqFile + " while other packages have hashes. Integrity cannot be verified.",
				})
			}
		}

		if strings.Contains(reqFile, "requirements.txt") {
			checkPipGitSources(dir, reqFile, &issues)
		}
	}

	return issues
}

func checkPipGitSources(dir, reqFile string, issues *[]ProvenanceIssue) {
	path := filepath.Join(dir, reqFile)
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := safefile.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "git+") || strings.HasPrefix(line, "-e git+") ||
			strings.Contains(line, "github.com") && strings.Contains(line, ".git") {
			name := extractPipGitPackageName(line)
			*issues = append(*issues, ProvenanceIssue{
				Package:     name,
				File:        reqFile,
				IssueType:   "git_source",
				Description: "Package '" + name + "' is installed from a git source. Registry provenance is not available.",
			})
		}
	}
}

func extractPipGitPackageName(line string) string {
	if idx := strings.Index(line, "#egg="); idx != -1 {
		return line[idx+5:]
	}
	parts := strings.Split(line, "/")
	if len(parts) > 0 {
		last := parts[len(parts)-1]
		last = strings.TrimSuffix(last, ".git")
		return last
	}
	return line
}

// CheckCargoChecksums scans Cargo.lock for packages missing checksum fields.
func CheckCargoChecksums(dir string) []ProvenanceIssue {
	lockPath := filepath.Join(dir, "Cargo.lock")
	f, err := os.Open(lockPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var issues []ProvenanceIssue
	scanner := safefile.NewScanner(f)
	var currentName, currentSource string
	hasChecksum := false
	inPackage := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			if inPackage && currentName != "" && !hasChecksum && currentSource != "" {
				if !strings.Contains(currentSource, "path+") {
					issueType := "missing_integrity"
					desc := "Crate '" + currentName + "' is missing a checksum in Cargo.lock."
					if strings.Contains(currentSource, "git+") {
						issueType = "git_source"
						desc = "Crate '" + currentName + "' is sourced from git. Registry provenance is not available."
					}
					issues = append(issues, ProvenanceIssue{
						Package:   currentName,
						File:      "Cargo.lock",
						IssueType: issueType,
						Description: desc,
					})
				}
			}
			currentName = ""
			currentSource = ""
			hasChecksum = false
			inPackage = true
			continue
		}

		if inPackage {
			if strings.HasPrefix(line, "name = ") {
				currentName = extractQuoted(line)
			} else if strings.HasPrefix(line, "source = ") {
				currentSource = extractQuoted(line)
			} else if strings.HasPrefix(line, "checksum = ") {
				hasChecksum = true
			}
		}
	}

	if inPackage && currentName != "" && !hasChecksum && currentSource != "" {
		if !strings.Contains(currentSource, "path+") {
			issueType := "missing_integrity"
			desc := "Crate '" + currentName + "' is missing a checksum in Cargo.lock."
			if strings.Contains(currentSource, "git+") {
				issueType = "git_source"
				desc = "Crate '" + currentName + "' is sourced from git. Registry provenance is not available."
			}
			issues = append(issues, ProvenanceIssue{
				Package:   currentName,
				File:      "Cargo.lock",
				IssueType: issueType,
				Description: desc,
			})
		}
	}

	return issues
}

// CheckNuGetContentHash scans packages.lock.json for packages missing contentHash.
func CheckNuGetContentHash(dir string) []ProvenanceIssue {
	lockPath := filepath.Join(dir, "packages.lock.json")
	data, err := safefile.ReadFile(lockPath)
	if err != nil {
		return nil
	}

	var lock struct {
		Dependencies map[string]map[string]struct {
			ContentHash string `json:"contentHash"`
			Resolved    string `json:"resolved"`
			Type        string `json:"type"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}

	var issues []ProvenanceIssue
	for _, framework := range lock.Dependencies {
		for name, dep := range framework {
			if dep.ContentHash == "" && dep.Resolved != "" {
				issues = append(issues, ProvenanceIssue{
					Package:     name,
					File:        "packages.lock.json",
					IssueType:   "missing_integrity",
					Description: "Package '" + name + "' is missing a contentHash in the lockfile. Integrity cannot be verified.",
				})
			}
		}
	}

	return issues
}

// CheckCIProvenanceWorkflow scans GitHub Actions for SLSA/Sigstore provenance configuration.
func CheckCIProvenanceWorkflow(dir string) *ProvenanceIssue {
	workflowDir := filepath.Join(dir, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return nil
	}

	slsaPatterns := []string{
		"slsa-framework/slsa-github-generator",
		"sigstore/cosign-installer",
		"actions/attest-build-provenance",
		"slsa-framework/slsa-verifier",
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		data, err := safefile.ReadFile(filepath.Join(workflowDir, name))
		if err != nil {
			continue
		}

		content := string(data)
		for _, pattern := range slsaPatterns {
			if strings.Contains(content, pattern) {
				return nil
			}
		}
	}

	return &ProvenanceIssue{
		File:        ".github/workflows/",
		IssueType:   "no_slsa_workflow",
		Description: "No SLSA/Sigstore provenance generation is configured in any GitHub Actions workflow. Consider adding build provenance attestation.",
	}
}

func isGitOrURLSource(resolved string) bool {
	return strings.HasPrefix(resolved, "git+") ||
		strings.HasPrefix(resolved, "git://") ||
		strings.HasPrefix(resolved, "file:") ||
		strings.HasSuffix(resolved, ".tgz") && !strings.Contains(resolved, "registry.npmjs.org") ||
		strings.Contains(resolved, "github.com") && strings.HasSuffix(resolved, ".tar.gz")
}

func extractQuoted(line string) string {
	idx := strings.Index(line, "\"")
	if idx == -1 {
		return ""
	}
	end := strings.Index(line[idx+1:], "\"")
	if end == -1 {
		return ""
	}
	return line[idx+1 : idx+1+end]
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
