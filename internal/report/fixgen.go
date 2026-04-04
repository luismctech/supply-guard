package report

import (
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

// EnrichWithFixes populates deterministic FixSuggestion fields on findings
// where an automated fix can be derived from the check type and context.
func EnrichWithFixes(findings []types.Finding) {
	for i := range findings {
		if findings[i].Fix != nil {
			continue
		}
		findings[i].Fix = suggestFix(&findings[i])
	}
}

func suggestFix(f *types.Finding) *types.FixSuggestion {
	switch f.CheckID {
	case types.CheckConfigHardening:
		return suggestHardeningFix(f)
	case types.CheckActionsPinning:
		return &types.FixSuggestion{
			Type:        "replace",
			File:        f.File,
			Line:        f.Line,
			Description: "Pin the GitHub Action to a full commit SHA. Find the SHA for the current tag at the action's GitHub repository under Releases or Tags.",
		}
	case types.CheckVersionRange:
		return suggestVersionRangeFix(f)
	case types.CheckCIInstall:
		return &types.FixSuggestion{
			Type:        "replace",
			File:        f.File,
			Line:        f.Line,
			Description: "Replace the unsafe install command with a lockfile-based install (npm ci, pip install -r requirements.txt --require-hashes, etc.).",
		}
	case types.CheckLockfileIntegrity:
		return &types.FixSuggestion{
			Type:        "command",
			Description: "Regenerate the lockfile by running the appropriate command for your ecosystem (npm install, pip freeze, cargo generate-lockfile).",
		}
	case types.CheckTyposquatting:
		return &types.FixSuggestion{
			Type:        "replace",
			File:        f.File,
			Description: "Verify the package name is correct. If this is a typosquatting attempt, remove the dependency and replace it with the legitimate package.",
		}
	case types.CheckPhantomDependency:
		return suggestPhantomFix(f)
	case types.CheckNetworkCalls:
		return &types.FixSuggestion{
			Type:        "replace",
			File:        f.File,
			Line:        f.Line,
			Description: "Review and remove suspicious network calls from install/build scripts. Legitimate dependencies should use package registry URLs only.",
		}
	case types.CheckProvenance:
		return &types.FixSuggestion{
			Type:        "add",
			File:        f.File,
			Description: "Add integrity hashes or provenance verification. For npm: ensure package-lock.json has 'integrity' fields. For pip: use --require-hashes. For CI: add SLSA provenance generation.",
		}
	default:
		return nil
	}
}

func suggestHardeningFix(f *types.Finding) *types.FixSuggestion {
	switch f.Ecosystem {
	case "npm":
		return &types.FixSuggestion{
			Type:       "add",
			File:       ".npmrc",
			NewContent: "ignore-scripts=true\naudit=true\n",
			Description: "Create or update .npmrc with security-hardened defaults.",
		}
	case "pip":
		return &types.FixSuggestion{
			Type:        "config_change",
			Description: "Generate a requirements.txt with pinned versions and hashes: pip freeze > requirements.txt",
		}
	default:
		return &types.FixSuggestion{
			Type:        "config_change",
			Description: f.Remediation,
		}
	}
}

func suggestVersionRangeFix(f *types.Finding) *types.FixSuggestion {
	if f.Package == "" {
		return nil
	}
	return &types.FixSuggestion{
		Type:        "replace",
		File:        f.File,
		Description: "Pin " + f.Package + " to an exact version instead of using a permissive range. Replace wildcards (*, x) or broad ranges (>=) with exact versions from your lockfile.",
	}
}

func suggestPhantomFix(f *types.Finding) *types.FixSuggestion {
	if f.Package == "" {
		return nil
	}
	return &types.FixSuggestion{
		Type:       "command",
		NewContent: "npm install " + f.Package + " --save",
		Description: "Add " + f.Package + " as an explicit dependency since it's imported in code but not declared in package.json.",
	}
}
