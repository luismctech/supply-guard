package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestSetDefaults(t *testing.T) {
	viper.Reset()
	SetDefaults()

	tests := []struct {
		key  string
		want any
	}{
		{"output", "table"},
		{"ecosystems.npm.enabled", true},
		{"ecosystems.pip.enabled", true},
		{"ecosystems.cargo.enabled", true},
		{"ecosystems.nuget.enabled", true},
		{"ecosystems.maven.enabled", true},
		{"ecosystems.gradle.enabled", true},
		{"checks.dependency_age_days", 7},
		{"checks.version_range_strictness", "conservative"},
	}

	for _, tt := range tests {
		got := viper.Get(tt.key)
		if got != tt.want {
			t.Errorf("viper.Get(%q) = %v (%T), want %v (%T)", tt.key, got, got, tt.want, tt.want)
		}
	}
}

func TestLoad_Defaults(t *testing.T) {
	viper.Reset()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Output != "table" {
		t.Errorf("cfg.Output = %q, want %q", cfg.Output, "table")
	}
	if !cfg.Ecosystems.Npm.Enabled {
		t.Error("npm should be enabled by default")
	}
	if cfg.Checks.DependencyAgeDays != 7 {
		t.Errorf("dependency_age_days = %d, want 7", cfg.Checks.DependencyAgeDays)
	}
	if cfg.Checks.VersionRangeStrictness != "conservative" {
		t.Errorf("version_range_strictness = %q, want %q", cfg.Checks.VersionRangeStrictness, "conservative")
	}
}

func TestLoad_DisabledChecks(t *testing.T) {
	viper.Reset()
	viper.Set("checks.disabled", []string{"SG001", "SG002"})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(cfg.Checks.Disabled) != 2 {
		t.Errorf("expected 2 disabled checks, got %d", len(cfg.Checks.Disabled))
	}
}

func TestLoad_IgnoreRules(t *testing.T) {
	viper.Reset()
	viper.Set("ignore_rules", []map[string]any{
		{"check": "SG006", "package": "my-pkg", "reason": "false positive"},
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(cfg.IgnoreRules) != 1 {
		t.Fatalf("expected 1 ignore rule, got %d", len(cfg.IgnoreRules))
	}
	if cfg.IgnoreRules[0].Check != "SG006" {
		t.Errorf("expected check SG006, got %q", cfg.IgnoreRules[0].Check)
	}
}
