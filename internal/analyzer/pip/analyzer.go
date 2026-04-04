package pip

import (
	"context"
	"os"
	"path/filepath"

	"github.com/AlbertoMZCruz/supply-guard/internal/analyzer"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

var _ analyzer.Analyzer = (*PipAnalyzer)(nil)

func init() {
	analyzer.Register(&PipAnalyzer{})
}

type PipAnalyzer struct{}

func (a *PipAnalyzer) Name() string      { return "pip" }
func (a *PipAnalyzer) Ecosystem() string  { return "pip" }

func (a *PipAnalyzer) Detect(dir string) bool {
	candidates := []string{
		"requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
		"Pipfile", "Pipfile.lock",
		"pyproject.toml", "poetry.lock",
		"setup.py", "setup.cfg",
		"pdm.lock", "uv.lock",
	}
	for _, f := range candidates {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

func (a *PipAnalyzer) Analyze(ctx context.Context, dir string, cfg *config.Config) ([]types.Finding, error) {
	pf := loadPipProjectFiles(dir)
	var findings []types.Finding

	findings = append(findings, checkPipLockfile(dir)...)
	findings = append(findings, checkPipIOCsCached(pf)...)
	findings = append(findings, checkPipTyposquattingCached(pf)...)
	findings = append(findings, checkPthFiles(dir)...)
	findings = append(findings, checkPipHardening(dir)...)
	findings = append(findings, checkPipVersionRangesCached(pf, cfg.Checks.VersionRangeStrictness)...)
	findings = append(findings, checkPipNetworkCalls(dir)...)
	findings = append(findings, checkPipProvenance(dir)...)

	return findings, nil
}
