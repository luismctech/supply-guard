package cargo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkCargoVersionRanges(dir string, strictness string) []types.Finding {
	var findings []types.Finding

	tomlPath := filepath.Join(dir, "Cargo.toml")
	f, err := os.Open(tomlPath)
	if err != nil {
		return findings
	}
	defer f.Close()

	threshold := check.DefaultRiskThreshold(strictness)
	scanner := safefile.NewScanner(f)
	lineNum := 0
	inDeps := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") {
			inDeps = line == "[dependencies]" || line == "[dev-dependencies]" || line == "[build-dependencies]"
			continue
		}

		if !inDeps || line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		name, version := parseCargoDepLine(line)
		if name == "" || version == "" {
			continue
		}

		cl := check.ClassifyCargoRange(version)
		if cl.Risk < threshold {
			continue
		}

		findings = append(findings, types.Finding{
			CheckID:   types.CheckVersionRange,
			Severity:  check.DefaultRangeSeverity(cl.Risk),
			Ecosystem: "cargo",
			Package:   name,
			Version:   version,
			File:      "Cargo.toml",
			Line:      lineNum,
			Title:     fmt.Sprintf("Permissive version range (%s): %s", cl.Risk, name),
			Description: fmt.Sprintf(
				"Crate '%s' uses version '%s' (%s). Cargo.lock pins the resolved version, but 'cargo update' can pull newer ones.",
				name, version, cl.Explanation,
			),
			Remediation: fmt.Sprintf("Pin with '=' prefix: %s = \"=%s\"", name, strings.TrimLeft(version, "^~><=!")),
		})
	}

	return findings
}

// parseCargoDepLine extracts name and version from lines like:
//
//	serde = "1.0.200"
//	tokio = { version = "1.37", features = ["full"] }
func parseCargoDepLine(line string) (string, string) {
	eqIdx := strings.Index(line, "=")
	if eqIdx == -1 {
		return "", ""
	}

	name := strings.TrimSpace(line[:eqIdx])
	rest := strings.TrimSpace(line[eqIdx+1:])

	if strings.HasPrefix(rest, "\"") {
		return name, extractTomlString(line[eqIdx+1:])
	}

	if strings.HasPrefix(rest, "{") {
		vIdx := strings.Index(rest, "version")
		if vIdx == -1 {
			return name, ""
		}
		afterVersion := rest[vIdx+len("version"):]
		eqIdx2 := strings.Index(afterVersion, "=")
		if eqIdx2 == -1 {
			return name, ""
		}
		return name, extractTomlString(afterVersion[eqIdx2+1:])
	}

	return "", ""
}

