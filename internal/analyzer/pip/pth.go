package pip

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkPthFiles(dir string) []types.Finding {
	var findings []types.Finding

	skipDirs := []string{".git", "__pycache__", ".tox", "node_modules", ".venv", "venv"}
	_ = safefile.WalkDir(dir, skipDirs, func(path string, d os.DirEntry) error {
		if !strings.HasSuffix(d.Name(), ".pth") {
			return nil
		}

		content, err := safefile.ReadFile(path)
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(dir, path)
		if relPath == "" {
			relPath = path
		}

		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "import\t") {
				findings = append(findings, types.Finding{
					CheckID:  types.CheckInstallScripts,
					Severity: types.SeverityCritical,
					Ecosystem: "pip",
					File:     relPath,
					Line:     i + 1,
					Title:    "Auto-executing .pth file detected",
					Description: "File '" + relPath + "' contains an import statement that executes code automatically " +
						"when Python starts. This was the exact technique used by TeamPCP to backdoor LiteLLM in March 2026.",
					Remediation: "Review the .pth file content. If not intentional, delete it and investigate how it was created.",
				})
			}
		}

		return nil
	})

	return findings
}
