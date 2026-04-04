package policy

import (
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type Rule struct {
	ID          string         `yaml:"id" json:"id"`
	Description string         `yaml:"description" json:"description"`
	Severity    types.Severity `yaml:"severity" json:"severity"`
	Enabled     bool           `yaml:"enabled" json:"enabled"`
	Config      map[string]any `yaml:"config,omitempty" json:"config,omitempty"`
}

type Policy struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}

type Engine struct {
	policy *Policy
}

func NewEngine(policy *Policy) *Engine {
	return &Engine{policy: policy}
}

func (e *Engine) IsCheckEnabled(checkID types.CheckID) bool {
	if e.policy == nil {
		return true
	}

	ruleID := checkIDToRuleID(checkID)
	for _, rule := range e.policy.Rules {
		if rule.ID == ruleID {
			return rule.Enabled
		}
	}
	return true
}

// FilterFindings removes findings for disabled checks and adjusts severity based on policy.
func (e *Engine) FilterFindings(findings []types.Finding) []types.Finding {
	if e.policy == nil {
		return findings
	}

	var filtered []types.Finding
	for _, f := range findings {
		if !e.IsCheckEnabled(f.CheckID) {
			continue
		}

		// Override severity if policy specifies one
		ruleID := checkIDToRuleID(f.CheckID)
		for _, rule := range e.policy.Rules {
			if rule.ID == ruleID && rule.Severity != "" {
				f.Severity = rule.Severity
				break
			}
		}

		filtered = append(filtered, f)
	}
	return filtered
}

var checkIDMapping = map[types.CheckID]string{
	types.CheckLockfileIntegrity:  "require-lockfile",
	types.CheckInstallScripts:    "no-install-scripts",
	types.CheckIOCMatch:          "block-known-malicious",
	types.CheckDependencyAge:     "dependency-age",
	types.CheckPhantomDependency: "no-phantom-deps",
	types.CheckTyposquatting:     "typosquatting-check",
	types.CheckConfigHardening:   "hardened-config",
	types.CheckActionsPinning:    "actions-sha-pinning",
	types.CheckProvenance:        "provenance-verification",
	types.CheckNetworkCalls:      "no-network-calls",
	types.CheckVersionRange:      "version-range-permissiveness",
	types.CheckCIInstall:         "ci-install-audit",
}

func checkIDToRuleID(checkID types.CheckID) string {
	if id, ok := checkIDMapping[checkID]; ok {
		return id
	}
	return string(checkID)
}
