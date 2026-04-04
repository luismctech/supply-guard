package maven

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkMavenVersionRanges(mf *mavenProjectFiles, strictness string) []types.Finding {
	var findings []types.Finding

	threshold := check.DefaultRiskThreshold(strictness)
	pom := mf.pom

	for _, dep := range pom.Dependencies.Dependencies {
		fullName := dep.GroupID + ":" + dep.ArtifactID
		cl := check.ClassifyMavenRange(dep.Version)
		if cl.Risk < threshold {
			continue
		}
		findings = append(findings, types.Finding{
			CheckID:   types.CheckVersionRange,
			Severity:  check.DefaultRangeSeverity(cl.Risk),
			Ecosystem: "maven",
			Package:   fullName,
			Version:   dep.Version,
			File:      "pom.xml",
			Title:     fmt.Sprintf("Permissive version range (%s): %s", cl.Risk, fullName),
			Description: fmt.Sprintf(
				"Dependency '%s' uses version '%s' (%s).",
				fullName, dep.Version, cl.Explanation,
			),
			Remediation: "Set an explicit version and use maven-enforcer-plugin to enforce version convergence",
		})
	}

	return findings
}

func checkGradleVersionRanges(dir string, strictness string) []types.Finding {
	var findings []types.Finding

	threshold := check.DefaultRiskThreshold(strictness)

	for _, buildFile := range []string{"build.gradle", "build.gradle.kts"} {
		buildPath := filepath.Join(dir, buildFile)
		f, err := os.Open(buildPath)
		if err != nil {
			continue
		}

		scanner := safefile.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())

			name, version := parseGradleDependencyLine(line)
			if name == "" {
				continue
			}

			cl := check.ClassifyGradleRange(version)
			if cl.Risk < threshold {
				continue
			}
			findings = append(findings, types.Finding{
				CheckID:   types.CheckVersionRange,
				Severity:  check.DefaultRangeSeverity(cl.Risk),
				Ecosystem: "gradle",
				Package:   name,
				Version:   version,
				File:      buildFile,
				Line:      lineNum,
				Title:     fmt.Sprintf("Permissive version range (%s): %s", cl.Risk, name),
				Description: fmt.Sprintf(
					"Dependency '%s' uses version '%s' (%s).",
					name, version, cl.Explanation,
				),
				Remediation: "Pin to an exact version",
			})
		}
		f.Close()
	}

	return findings
}

// parseGradleDependencyLine extracts group:artifact:version from common Gradle patterns.
func parseGradleDependencyLine(line string) (string, string) {
	// Match patterns like: implementation 'group:artifact:version'
	// or: implementation("group:artifact:version")
	for _, prefix := range []string{
		"implementation", "api", "compileOnly", "runtimeOnly",
		"testImplementation", "testRuntimeOnly", "classpath",
	} {
		if !strings.Contains(line, prefix) {
			continue
		}

		// Extract quoted string
		var dep string
		for _, q := range []byte{'"', '\''} {
			start := strings.IndexByte(line, q)
			if start == -1 {
				continue
			}
			end := strings.IndexByte(line[start+1:], q)
			if end == -1 {
				continue
			}
			dep = line[start+1 : start+1+end]
			break
		}

		if dep == "" {
			continue
		}

		parts := strings.SplitN(dep, ":", 3)
		if len(parts) == 3 {
			name := parts[0] + ":" + parts[1]
			return name, parts[2]
		}
	}

	return "", ""
}

