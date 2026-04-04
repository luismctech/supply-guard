package check

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// CIInstallIssue represents an unsafe install command found in a CI workflow.
type CIInstallIssue struct {
	File    string
	Line    int
	Command string
	Reason  string
}

// CheckCIInstallCommands scans GitHub Actions workflows for unsafe install commands.
func CheckCIInstallCommands(dir string) []CIInstallIssue {
	workflowDir := filepath.Join(dir, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return nil
	}

	var issues []CIInstallIssue
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		filePath := filepath.Join(workflowDir, name)
		issues = append(issues, scanForUnsafeInstalls(filePath)...)
	}

	return issues
}

func scanForUnsafeInstalls(path string) []CIInstallIssue {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var issues []CIInstallIssue
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)
	lineNum := 0
	inMultiLine := false
	multiLineIndent := 0
	multiLineStart := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if inMultiLine {
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if indent > multiLineIndent && trimmed != "" {
				if issue := classifyInstallCommand(trimmed, path, lineNum); issue != nil {
					issues = append(issues, *issue)
				}
				continue
			}
			inMultiLine = false
		}

		if !strings.Contains(trimmed, "run:") {
			continue
		}

		parts := strings.SplitN(trimmed, "run:", 2)
		if len(parts) != 2 {
			continue
		}

		cmd := strings.TrimSpace(parts[1])

		if cmd == "|" || cmd == "|-" || cmd == "|+" {
			inMultiLine = true
			runKeyIdx := strings.Index(line, "run:")
			multiLineIndent = runKeyIdx
			multiLineStart = lineNum
			_ = multiLineStart
			continue
		}

		if cmd == "" {
			continue
		}

		if issue := classifyInstallCommand(cmd, path, lineNum); issue != nil {
			issues = append(issues, *issue)
		}
	}

	return issues
}

func classifyInstallCommand(cmd, file string, line int) *CIInstallIssue {
	cmd = strings.TrimSpace(cmd)

	// npm install instead of npm ci
	if (strings.Contains(cmd, "npm install") || strings.Contains(cmd, "npm i ")) &&
		!strings.Contains(cmd, "npm ci") &&
		!strings.Contains(cmd, "npm install -g") &&
		!strings.Contains(cmd, "npm i -g") {
		return &CIInstallIssue{
			File:    file,
			Line:    line,
			Command: cmd,
			Reason:  "Use 'npm ci' instead of 'npm install' in CI to respect the lockfile and get deterministic builds",
		}
	}

	// pip install without --require-hashes
	if strings.Contains(cmd, "pip install") &&
		strings.Contains(cmd, "-r ") &&
		!strings.Contains(cmd, "--require-hashes") {
		return &CIInstallIssue{
			File:    file,
			Line:    line,
			Command: cmd,
			Reason:  "Add '--require-hashes' to pip install to verify package integrity against known hashes",
		}
	}

	return nil
}
