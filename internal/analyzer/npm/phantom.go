package npm

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkPhantomDeps(pf *projectFiles) []types.Finding {
	var findings []types.Finding

	if pf.pkg == nil {
		return findings
	}

	sourceImports := collectImports(pf.dir)

	for name := range pf.pkg.Dependencies {
		if isKnownNonImport(name) {
			continue
		}

		importName := normalizeImportName(name)
		if !sourceImports[importName] && !sourceImports[name] {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckPhantomDependency,
				Severity:    types.SeverityLow,
				Ecosystem:   "npm",
				Package:     name,
				File:        "package.json",
				Title:       "Phantom dependency detected",
				Description: "Package '" + name + "' is declared in dependencies but never imported in source code. Phantom dependencies increase attack surface without providing value.",
				Remediation: "If the package is unused, remove it with 'npm uninstall " + name + "'. If it's used indirectly (e.g., a CLI tool), move it to devDependencies.",
			})
		}
	}

	return findings
}

func collectImports(dir string) map[string]bool {
	imports := make(map[string]bool)

	extensions := map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true}
	skipDirs := []string{"node_modules", ".git", "dist", "build", ".next"}

	_ = safefile.WalkDir(dir, skipDirs, func(path string, d os.DirEntry) error {
		if !extensions[filepath.Ext(path)] {
			return nil
		}

		data, err := safefile.ReadFile(path)
		if err != nil {
			return nil
		}

		extractImportNames(string(data), imports)
		return nil
	})

	return imports
}

func extractImportNames(content string, imports map[string]bool) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// require('package') or require("package")
		if idx := strings.Index(trimmed, "require("); idx != -1 {
			name := extractStringArg(trimmed[idx+8:])
			if name != "" && !strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "/") {
				imports[extractPackageName(name)] = true
			}
		}

		// import ... from 'package' or import ... from "package"
		if strings.Contains(trimmed, " from ") {
			parts := strings.SplitN(trimmed, " from ", 2)
			if len(parts) == 2 {
				name := extractQuotedString(parts[1])
				if name != "" && !strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "/") {
					imports[extractPackageName(name)] = true
				}
			}
		}

		// import 'package' (side-effect imports)
		if strings.HasPrefix(trimmed, "import ") && !strings.Contains(trimmed, " from ") {
			name := extractQuotedString(trimmed[7:])
			if name != "" && !strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "/") {
				imports[extractPackageName(name)] = true
			}
		}
	}
}

func extractStringArg(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 3 {
		return ""
	}
	quote := s[0]
	if quote != '\'' && quote != '"' && quote != '`' {
		return ""
	}
	end := strings.IndexByte(s[1:], quote)
	if end == -1 {
		return ""
	}
	return s[1 : end+1]
}

func extractQuotedString(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, ";")
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return ""
	}
	quote := s[0]
	if quote != '\'' && quote != '"' {
		return ""
	}
	end := strings.IndexByte(s[1:], quote)
	if end == -1 {
		return ""
	}
	return s[1 : end+1]
}

// extractPackageName gets the package name from an import path.
// "@scope/pkg/sub" -> "@scope/pkg", "pkg/sub" -> "pkg"
func extractPackageName(importPath string) string {
	if strings.HasPrefix(importPath, "@") {
		parts := strings.SplitN(importPath, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return importPath
	}
	parts := strings.SplitN(importPath, "/", 2)
	return parts[0]
}

func normalizeImportName(pkgName string) string {
	return strings.ToLower(pkgName)
}

var knownNonImports = map[string]bool{
	"typescript":   true,
	"@types/node":  true,
	"eslint":       true,
	"prettier":     true,
	"nodemon":      true,
	"ts-node":      true,
	"tsx":          true,
	"concurrently": true,
	"husky":        true,
	"lint-staged":  true,
	"tailwindcss":  true,
	"autoprefixer": true,
	"postcss":      true,
}

func isKnownNonImport(name string) bool {
	if knownNonImports[name] {
		return true
	}
	return strings.HasPrefix(name, "@types/")
}
