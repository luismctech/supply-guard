package pip

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkPipHardening(dir string) []types.Finding {
	var findings []types.Finding

	// Check pip.conf / pip.ini for security settings
	pipConfPaths := []string{
		filepath.Join(dir, "pip.conf"),
		filepath.Join(dir, ".pip", "pip.conf"),
	}

	for _, confPath := range pipConfPaths {
		if _, err := os.Stat(confPath); err == nil {
			findings = append(findings, checkPipConfSecurity(confPath)...)
		}
	}

	// Check if requirements.txt uses --require-hashes
	reqPath := filepath.Join(dir, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		if !usesHashes(reqPath) {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckConfigHardening,
				Severity:    types.SeverityLow,
				Ecosystem:   "pip",
				File:        "requirements.txt",
				Title:       "Requirements not using hash verification",
				Description: "requirements.txt does not use --hash flags. Hash verification ensures packages haven't been tampered with on the registry.",
				Remediation: "Use 'pip-compile --generate-hashes' or add '--hash=sha256:...' to each requirement",
			})
		}
	}

	return findings
}

func checkPipConfSecurity(path string) []types.Finding {
	var findings []types.Finding

	f, err := os.Open(path)
	if err != nil {
		return findings
	}
	defer f.Close()

	hasRequireHashes := false
	scanner := safefile.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "require-hashes") && strings.Contains(line, "true") {
			hasRequireHashes = true
		}
	}

	if !hasRequireHashes {
		findings = append(findings, types.Finding{
			CheckID:     types.CheckConfigHardening,
			Severity:    types.SeverityLow,
			Ecosystem:   "pip",
			File:        path,
			Title:       "pip.conf missing require-hashes",
			Description: "pip.conf does not set require-hashes = true. Without hash verification, pip cannot detect tampered packages.",
			Remediation: "Add 'require-hashes = true' under [install] in pip.conf",
		})
	}

	return findings
}

func usesHashes(reqPath string) bool {
	f, err := os.Open(reqPath)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := safefile.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "--hash=") {
			return true
		}
	}
	return false
}
