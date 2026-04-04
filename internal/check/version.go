package check

import (
	"regexp"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

// VersionRisk classifies how permissive a version range is.
type VersionRisk int

const (
	RiskExact        VersionRisk = iota // single version, no flexibility
	RiskConservative                    // patch-only updates (~1.2.3)
	RiskPermissive                      // minor+patch updates (^1.2.3)
	RiskDangerous                       // unbounded or tag-based (*, latest, >=1.0.0)
)

func (r VersionRisk) String() string {
	switch r {
	case RiskExact:
		return "exact"
	case RiskConservative:
		return "conservative"
	case RiskPermissive:
		return "permissive"
	case RiskDangerous:
		return "dangerous"
	default:
		return "unknown"
	}
}

// RangeClassification is the result of analyzing a version specifier.
type RangeClassification struct {
	Risk        VersionRisk
	Original    string
	Explanation string
}

var (
	semverExact    = regexp.MustCompile(`^\d+\.\d+\.\d+(-[\w.]+)?$`)
	nugetFourPart  = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	mavenLoose     = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)
)

// --- npm ---

func ClassifyNpmRange(version string) RangeClassification {
	v := strings.TrimSpace(version)
	orig := v

	switch {
	case v == "" || v == "*" || v == "latest" || v == "next":
		return RangeClassification{RiskDangerous, orig, "unbounded or tag-based version"}

	case strings.HasPrefix(v, "git+") || strings.HasPrefix(v, "git://") ||
		strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") ||
		strings.HasPrefix(v, "github:"):
		return RangeClassification{RiskDangerous, orig, "git/URL dependency bypasses registry integrity"}

	case strings.Contains(v, " || "):
		return RangeClassification{RiskDangerous, orig, "union range can match many versions"}

	case strings.HasPrefix(v, ">=") && !strings.Contains(v, "<") && !strings.Contains(v, " "):
		return RangeClassification{RiskDangerous, orig, "lower-bound only, allows any newer version"}

	case strings.HasPrefix(v, "^0.0."):
		return RangeClassification{RiskExact, orig, "^0.0.x is effectively exact in npm"}

	case strings.HasPrefix(v, "^0."):
		return RangeClassification{RiskConservative, orig, "^0.x allows patch updates only"}

	case strings.HasPrefix(v, "^"):
		return RangeClassification{RiskPermissive, orig, "caret allows minor+patch updates"}

	case strings.HasPrefix(v, "~"):
		return RangeClassification{RiskConservative, orig, "tilde allows patch updates only"}

	case semverExact.MatchString(v):
		return RangeClassification{RiskExact, orig, "exact version"}

	case strings.Contains(v, " - "):
		return RangeClassification{RiskPermissive, orig, "hyphen range allows a span of versions"}

	case strings.Contains(v, ".x") || strings.Contains(v, ".X"):
		return RangeClassification{RiskPermissive, orig, "partial version acts as a range"}

	default:
		if semverExact.MatchString(strings.TrimPrefix(v, "=")) {
			return RangeClassification{RiskExact, orig, "exact version"}
		}
		return RangeClassification{RiskPermissive, orig, "non-standard range specifier"}
	}
}

// --- pip ---

func ClassifyPipRange(version string) RangeClassification {
	v := strings.TrimSpace(version)
	orig := v

	switch {
	case v == "" || v == "(no version)":
		return RangeClassification{RiskDangerous, orig, "no version constraint, installs latest"}

	case strings.HasPrefix(v, "=="):
		inner := strings.TrimPrefix(v, "==")
		if strings.Contains(inner, "*") {
			return RangeClassification{RiskPermissive, orig, "wildcard in exact pin (==1.*)"}
		}
		return RangeClassification{RiskExact, orig, "exact version"}

	case strings.HasPrefix(v, "~="):
		return RangeClassification{RiskConservative, orig, "compatible release, allows patch updates"}

	case strings.HasPrefix(v, ">=") && strings.Contains(v, ",") && strings.Contains(v, "<"):
		return RangeClassification{RiskPermissive, orig, "bounded range allows a span of versions"}

	case strings.HasPrefix(v, ">=") || strings.HasPrefix(v, ">"):
		return RangeClassification{RiskDangerous, orig, "lower-bound only, allows any newer version"}

	case strings.HasPrefix(v, "<=") || strings.HasPrefix(v, "<"):
		return RangeClassification{RiskDangerous, orig, "upper-bound only, underspecified constraint"}

	case strings.HasPrefix(v, "!="):
		return RangeClassification{RiskDangerous, orig, "exclusion only, allows almost any version"}

	default:
		return RangeClassification{RiskPermissive, orig, "non-standard version specifier"}
	}
}

// --- Cargo ---

func ClassifyCargoRange(version string) RangeClassification {
	v := strings.TrimSpace(version)
	orig := v

	switch {
	case v == "" || v == "*":
		return RangeClassification{RiskDangerous, orig, "wildcard allows any version"}

	case strings.HasPrefix(v, "="):
		return RangeClassification{RiskExact, orig, "exact version pin"}

	case strings.HasPrefix(v, "~"):
		return RangeClassification{RiskConservative, orig, "tilde allows patch updates only"}

	case strings.HasPrefix(v, ">=") && !strings.Contains(v, ","):
		return RangeClassification{RiskDangerous, orig, "lower-bound only, allows any newer version"}

	case strings.HasPrefix(v, ">=") && strings.Contains(v, ", <"):
		return RangeClassification{RiskPermissive, orig, "bounded range"}

	case strings.HasPrefix(v, "^"):
		return classifyCargoCaretOrBare(strings.TrimPrefix(v, "^"), orig)

	case strings.Contains(v, ".") && !strings.ContainsAny(v, "<>=!~^"):
		// Bare version in Cargo.toml is implicitly ^version
		return classifyCargoCaretOrBare(v, orig)

	default:
		return RangeClassification{RiskPermissive, orig, "non-standard range specifier"}
	}
}

func classifyCargoCaretOrBare(inner, orig string) RangeClassification {
	parts := strings.SplitN(inner, ".", 3)
	if len(parts) >= 1 && parts[0] == "0" {
		if len(parts) >= 2 && parts[1] == "0" {
			return RangeClassification{RiskExact, orig, "^0.0.x is effectively exact in Cargo"}
		}
		return RangeClassification{RiskConservative, orig, "^0.x allows patch updates only in Cargo"}
	}
	return RangeClassification{RiskPermissive, orig, "caret/default allows minor+patch updates"}
}

// --- NuGet ---

func ClassifyNugetRange(version string) RangeClassification {
	v := strings.TrimSpace(version)
	orig := v

	switch {
	case v == "" || v == "*":
		return RangeClassification{RiskDangerous, orig, "wildcard or missing version"}

	case strings.Contains(v, "*"):
		return RangeClassification{RiskPermissive, orig, "wildcard version (e.g. 13.*)"}

	case strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") && !strings.Contains(v, ","):
		return RangeClassification{RiskExact, orig, "exact bracket notation [x.y.z]"}

	case strings.HasPrefix(v, "[") || strings.HasPrefix(v, "("):
		if strings.Contains(v, ",)") || strings.Contains(v, ", )") {
			return RangeClassification{RiskDangerous, orig, "open upper bound in range"}
		}
		return RangeClassification{RiskPermissive, orig, "bounded range notation"}

	default:
		if semverExact.MatchString(v) || nugetFourPart.MatchString(v) {
			return RangeClassification{RiskExact, orig, "exact version"}
		}
		return RangeClassification{RiskPermissive, orig, "non-standard version format"}
	}
}

// --- Maven ---

func ClassifyMavenRange(version string) RangeClassification {
	v := strings.TrimSpace(version)
	orig := v
	upper := strings.ToUpper(v)

	switch {
	case v == "" || upper == "LATEST" || upper == "RELEASE":
		return RangeClassification{RiskDangerous, orig, "dynamic version resolves at build time"}

	case strings.HasPrefix(v, "${"):
		return RangeClassification{RiskPermissive, orig, "property reference, version resolved indirectly"}

	case strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") && !strings.Contains(v, ","):
		return RangeClassification{RiskExact, orig, "exact bracket notation"}

	case strings.HasPrefix(v, "[") || strings.HasPrefix(v, "("):
		if strings.HasSuffix(v, ",)") || strings.HasSuffix(v, ", )") {
			return RangeClassification{RiskDangerous, orig, "open upper bound in range"}
		}
		return RangeClassification{RiskPermissive, orig, "bounded range notation"}

	default:
		if semverExact.MatchString(v) || mavenLoose.MatchString(v) {
			return RangeClassification{RiskExact, orig, "exact version (soft requirement)"}
		}
		return RangeClassification{RiskPermissive, orig, "non-standard version format"}
	}
}

// --- Gradle ---

func ClassifyGradleRange(version string) RangeClassification {
	v := strings.TrimSpace(version)
	orig := v
	lower := strings.ToLower(v)

	switch {
	case v == "" || lower == "latest.release" || lower == "latest.integration":
		return RangeClassification{RiskDangerous, orig, "dynamic version resolves at build time"}

	case strings.HasSuffix(v, "+"):
		return RangeClassification{RiskDangerous, orig, "prefix match allows any newer patch/minor"}

	case strings.HasPrefix(v, "[") || strings.HasPrefix(v, "("):
		if strings.HasSuffix(v, ",)") || strings.HasSuffix(v, ", )") {
			return RangeClassification{RiskDangerous, orig, "open upper bound in range"}
		}
		return RangeClassification{RiskPermissive, orig, "bounded range notation"}

	default:
		if semverExact.MatchString(v) || mavenLoose.MatchString(v) {
			return RangeClassification{RiskExact, orig, "exact version"}
		}
		return RangeClassification{RiskPermissive, orig, "non-standard version format"}
	}
}

// DefaultRiskThreshold converts a strictness string to a VersionRisk threshold.
func DefaultRiskThreshold(strictness string) VersionRisk {
	switch strictness {
	case "exact":
		return RiskConservative
	case "permissive":
		return RiskDangerous
	default:
		return RiskPermissive
	}
}

// DefaultRangeSeverity maps a VersionRisk to a finding severity.
func DefaultRangeSeverity(risk VersionRisk) types.Severity {
	switch risk {
	case RiskDangerous:
		return types.SeverityHigh
	case RiskPermissive:
		return types.SeverityMedium
	case RiskConservative:
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}
