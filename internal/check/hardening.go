package check

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
)

type HardeningResult struct {
	File    string
	Missing []string
}

// CheckNpmrcHardening verifies that .npmrc has security-critical settings.
func CheckNpmrcHardening(dir string) *HardeningResult {
	npmrcPath := filepath.Join(dir, ".npmrc")
	result := &HardeningResult{File: ".npmrc"}

	required := map[string]bool{
		"ignore-scripts": false,
	}

	f, err := os.Open(npmrcPath)
	if err != nil {
		result.Missing = append(result.Missing, "ignore-scripts=true")
		return result
	}
	defer f.Close()

	scanner := safefile.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		if key == "ignore-scripts" && val == "true" {
			required["ignore-scripts"] = true
		}
	}

	for setting, found := range required {
		if !found {
			result.Missing = append(result.Missing, setting+"=true")
		}
	}

	return result
}

// CheckGitHubActionsPinning scans workflow files for Actions not pinned by SHA.
func CheckGitHubActionsPinning(dir string) []ActionPinIssue {
	workflowDir := filepath.Join(dir, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return nil
	}

	var issues []ActionPinIssue

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		filePath := filepath.Join(workflowDir, name)
		fileIssues := scanWorkflowFile(filePath)
		issues = append(issues, fileIssues...)
	}

	return issues
}

type ActionPinIssue struct {
	File   string
	Line   int
	Action string
}

func scanWorkflowFile(path string) []ActionPinIssue {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	relPath := path
	var issues []ActionPinIssue

	scanner := safefile.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(line, "uses:") && !strings.Contains(line, "uses:") {
			continue
		}

		parts := strings.SplitN(line, "uses:", 2)
		if len(parts) != 2 {
			continue
		}

		action := strings.TrimSpace(parts[1])
		action = strings.Trim(action, "\"'")

		if action == "" || strings.HasPrefix(action, "./") || strings.HasPrefix(action, "docker://") {
			continue
		}

		// Check if pinned by SHA (40-char hex after @)
		atIdx := strings.LastIndex(action, "@")
		if atIdx == -1 {
			issues = append(issues, ActionPinIssue{
				File:   relPath,
				Line:   lineNum,
				Action: action,
			})
			continue
		}

		ref := action[atIdx+1:]
		if !isSHA(ref) {
			issues = append(issues, ActionPinIssue{
				File:   relPath,
				Line:   lineNum,
				Action: action,
			})
		}
	}

	return issues
}

func isSHA(s string) bool {
	if len(s) < 40 {
		return false
	}
	s = s[:40]
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
