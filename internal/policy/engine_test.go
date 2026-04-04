package policy

import (
	"testing"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestIsCheckEnabled_NilPolicy(t *testing.T) {
	e := NewEngine(nil)
	if !e.IsCheckEnabled(types.CheckIOCMatch) {
		t.Error("nil policy should enable all checks")
	}
}

func TestIsCheckEnabled_EnabledRule(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{ID: "block-known-malicious", Enabled: true},
	}}
	e := NewEngine(p)
	if !e.IsCheckEnabled(types.CheckIOCMatch) {
		t.Error("expected IOC check to be enabled")
	}
}

func TestIsCheckEnabled_DisabledRule(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{ID: "block-known-malicious", Enabled: false},
	}}
	e := NewEngine(p)
	if e.IsCheckEnabled(types.CheckIOCMatch) {
		t.Error("expected IOC check to be disabled")
	}
}

func TestIsCheckEnabled_UnknownCheck(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{ID: "block-known-malicious", Enabled: false},
	}}
	e := NewEngine(p)
	if !e.IsCheckEnabled("SG999") {
		t.Error("unknown check should default to enabled")
	}
}

func TestFilterFindings_NilPolicy(t *testing.T) {
	e := NewEngine(nil)
	findings := []types.Finding{
		{CheckID: types.CheckIOCMatch, Severity: types.SeverityCritical},
	}
	got := e.FilterFindings(findings)
	if len(got) != 1 {
		t.Errorf("nil policy should pass all findings through, got %d", len(got))
	}
}

func TestFilterFindings_DisabledCheck(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{ID: "block-known-malicious", Enabled: false},
	}}
	e := NewEngine(p)
	findings := []types.Finding{
		{CheckID: types.CheckIOCMatch, Severity: types.SeverityCritical},
		{CheckID: types.CheckTyposquatting, Severity: types.SeverityHigh},
	}
	got := e.FilterFindings(findings)
	if len(got) != 1 {
		t.Errorf("expected 1 finding after filtering, got %d", len(got))
	}
	if got[0].CheckID != types.CheckTyposquatting {
		t.Errorf("expected typosquatting finding, got %s", got[0].CheckID)
	}
}

func TestFilterFindings_SeverityOverride(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{ID: "typosquatting-check", Enabled: true, Severity: types.SeverityLow},
	}}
	e := NewEngine(p)
	findings := []types.Finding{
		{CheckID: types.CheckTyposquatting, Severity: types.SeverityHigh},
	}
	got := e.FilterFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != types.SeverityLow {
		t.Errorf("expected severity override to low, got %s", got[0].Severity)
	}
}

func TestCheckIDToRuleID_KnownMapping(t *testing.T) {
	tests := []struct {
		checkID types.CheckID
		ruleID  string
	}{
		{types.CheckIOCMatch, "block-known-malicious"},
		{types.CheckTyposquatting, "typosquatting-check"},
		{types.CheckLockfileIntegrity, "require-lockfile"},
		{types.CheckVersionRange, "version-range-permissiveness"},
	}
	for _, tt := range tests {
		got := checkIDToRuleID(tt.checkID)
		if got != tt.ruleID {
			t.Errorf("checkIDToRuleID(%s) = %q, want %q", tt.checkID, got, tt.ruleID)
		}
	}
}

func TestCheckIDToRuleID_UnknownFallback(t *testing.T) {
	got := checkIDToRuleID("SG999")
	if got != "SG999" {
		t.Errorf("unknown check should return raw ID, got %q", got)
	}
}
