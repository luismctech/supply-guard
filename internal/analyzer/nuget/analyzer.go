package nuget

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/analyzer"
	"github.com/AlbertoMZCruz/supply-guard/internal/check"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

var _ analyzer.Analyzer = (*NuGetAnalyzer)(nil)

func init() {
	analyzer.Register(&NuGetAnalyzer{})
}

type NuGetAnalyzer struct{}

func (a *NuGetAnalyzer) Name() string      { return "nuget" }
func (a *NuGetAnalyzer) Ecosystem() string  { return "nuget" }

func (a *NuGetAnalyzer) Detect(dir string) bool {
	// Look for .csproj, .fsproj, .vbproj, packages.config, or .sln files
	patterns := []string{"*.csproj", "*.fsproj", "*.vbproj", "*.sln", "packages.config"}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		if len(matches) > 0 {
			return true
		}
	}
	// Also check subdirectories one level deep
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			for _, pattern := range []string{"*.csproj", "*.fsproj"} {
				matches, _ := filepath.Glob(filepath.Join(dir, entry.Name(), pattern))
				if len(matches) > 0 {
					return true
				}
			}
		}
	}
	return false
}

func (a *NuGetAnalyzer) Analyze(ctx context.Context, dir string, cfg *config.Config) ([]types.Finding, error) {
	nf := loadNuGetProjectFiles(dir)
	var findings []types.Finding

	findings = append(findings, checkNuGetLockfile(dir)...)
	findings = append(findings, checkNuGetIOCs(dir)...)
	findings = append(findings, checkNuGetVersionPinningCached(nf, cfg.Checks.VersionRangeStrictness)...)
	findings = append(findings, checkNuGetNetworkCalls(dir)...)
	findings = append(findings, checkNuGetProvenance(dir)...)
	findings = append(findings, checkNuGetTyposquattingCached(nf)...)

	return findings, nil
}

func checkNuGetLockfile(dir string) []types.Finding {
	var findings []types.Finding

	lockPath := filepath.Join(dir, "packages.lock.json")
	if _, err := os.Stat(lockPath); err != nil {
		if len(findCsprojFiles(dir)) > 0 {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckLockfileIntegrity,
				Severity:    types.SeverityMedium,
				Ecosystem:   "nuget",
				File:        "packages.lock.json",
				Title:       "No NuGet lockfile found",
				Description: ".csproj files exist but packages.lock.json is missing. Enable lockfile generation for reproducible builds.",
				Remediation: "Set <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile> in your .csproj and run 'dotnet restore'",
			})
		}
	}

	return findings
}

func findCsprojFiles(dir string) []string {
	var files []string
	skipDirs := []string{".git", "node_modules", "bin", "obj"}
	_ = safefile.WalkDir(dir, skipDirs, func(path string, d os.DirEntry) error {
		if strings.HasSuffix(d.Name(), ".csproj") || strings.HasSuffix(d.Name(), ".fsproj") {
			files = append(files, path)
		}
		return nil
	})
	return files
}

type nugetLockfile struct {
	Version      int                                    `json:"version"`
	Dependencies map[string]map[string]nugetLockedDep   `json:"dependencies"`
}

type nugetLockedDep struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

func checkNuGetIOCs(dir string) []types.Finding {
	var findings []types.Finding

	lockPath := filepath.Join(dir, "packages.lock.json")
	data, err := safefile.ReadFile(lockPath)
	if err != nil {
		return checkNuGetIOCsFromCsproj(dir)
	}

	var lock nugetLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return findings
	}

	for _, framework := range lock.Dependencies {
		for name, dep := range framework {
			match, err := check.CheckPackageIOC("nuget", name, dep.Resolved)
			if err != nil {
				continue
			}
			if match != nil {
				findings = append(findings, types.Finding{
					CheckID:     types.CheckIOCMatch,
					Severity:    types.SeverityCritical,
					Ecosystem:   "nuget",
					Package:     name,
					Version:     dep.Resolved,
					File:        "packages.lock.json",
					Title:       "Known malicious NuGet package detected",
					Description: match.Reason,
					Remediation: "Remove this package immediately",
				})
			}
		}
	}

	return findings
}

type csprojFile struct {
	XMLName    xml.Name        `xml:"Project"`
	ItemGroups []csprojItemGroup `xml:"ItemGroup"`
}

type csprojItemGroup struct {
	PackageRefs []csprojPackageRef `xml:"PackageReference"`
}

type csprojPackageRef struct {
	Include string `xml:"Include,attr"`
	Version string `xml:"Version,attr"`
}

func checkNuGetIOCsFromCsproj(dir string) []types.Finding {
	var findings []types.Finding

	csprojFiles, _ := filepath.Glob(filepath.Join(dir, "*.csproj"))
	for _, csprojPath := range csprojFiles {
		refs := parseCsproj(csprojPath)
		relPath, _ := filepath.Rel(dir, csprojPath)
		if relPath == "" {
			relPath = csprojPath
		}

		for _, ref := range refs {
			match, err := check.CheckPackageIOC("nuget", ref.Include, ref.Version)
			if err != nil {
				continue
			}
			if match != nil {
				findings = append(findings, types.Finding{
					CheckID:     types.CheckIOCMatch,
					Severity:    types.SeverityCritical,
					Ecosystem:   "nuget",
					Package:     ref.Include,
					Version:     ref.Version,
					File:        relPath,
					Title:       "Known malicious NuGet package detected",
					Description: match.Reason,
					Remediation: "Remove this package immediately",
				})
			}
		}
	}

	return findings
}

func parseCsproj(path string) []csprojPackageRef {
	data, err := safefile.ReadFile(path)
	if err != nil {
		return nil
	}

	var proj csprojFile
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil
	}

	var refs []csprojPackageRef
	for _, ig := range proj.ItemGroups {
		refs = append(refs, ig.PackageRefs...)
	}
	return refs
}

func checkNuGetVersionPinningCached(nf *nugetProjectFiles, strictness string) []types.Finding {
	var findings []types.Finding

	threshold := check.DefaultRiskThreshold(strictness)

	for csprojPath, refs := range nf.csprojMap {
		relPath, _ := filepath.Rel(nf.dir, csprojPath)
		if relPath == "" {
			relPath = csprojPath
		}

		for _, ref := range refs {
			cl := check.ClassifyNugetRange(ref.Version)
			if cl.Risk < threshold {
				continue
			}
			sev := check.DefaultRangeSeverity(cl.Risk)
			findings = append(findings, types.Finding{
				CheckID:   types.CheckVersionRange,
				Severity:  sev,
				Ecosystem: "nuget",
				Package:   ref.Include,
				Version:   ref.Version,
				File:      relPath,
				Title:     fmt.Sprintf("Permissive version range (%s): %s", cl.Risk, ref.Include),
				Description: fmt.Sprintf(
					"Package '%s' uses version '%s' (%s). Pin to an exact version for reproducible builds.",
					ref.Include, ref.Version, cl.Explanation,
				),
				Remediation: fmt.Sprintf("Pin to exact version: <PackageReference Include=\"%s\" Version=\"x.y.z\" />", ref.Include),
			})
		}
	}

	return findings
}

