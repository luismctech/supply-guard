package config

import (
	"github.com/spf13/viper"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type Config struct {
	Output      string            `mapstructure:"output"`
	Quiet       bool              `mapstructure:"quiet"`
	FailOn      []types.Severity  `mapstructure:"fail_on"`
	Ecosystems  EcosystemsConfig  `mapstructure:"ecosystems"`
	Checks      ChecksConfig      `mapstructure:"checks"`
	Ignore      []string          `mapstructure:"ignore"`
	IgnoreRules []IgnoreRule      `mapstructure:"ignore_rules"`
}

type EcosystemsConfig struct {
	Npm    EcosystemToggle `mapstructure:"npm"`
	Pip    EcosystemToggle `mapstructure:"pip"`
	Cargo  EcosystemToggle `mapstructure:"cargo"`
	Nuget  EcosystemToggle `mapstructure:"nuget"`
	Maven  EcosystemToggle `mapstructure:"maven"`
	Gradle EcosystemToggle `mapstructure:"gradle"`
}

type EcosystemToggle struct {
	Enabled bool `mapstructure:"enabled"`
}

type ChecksConfig struct {
	DependencyAgeDays      int      `mapstructure:"dependency_age_days"`
	Disabled               []string `mapstructure:"disabled"`
	VersionRangeStrictness string   `mapstructure:"version_range_strictness"`
}

// IgnoreRule allows granular suppression of specific findings.
// All non-empty fields must match for the rule to suppress a finding.
type IgnoreRule struct {
	Check   string `mapstructure:"check"`
	Package string `mapstructure:"package"`
	File    string `mapstructure:"file"`
	Reason  string `mapstructure:"reason"`
}

func SetDefaults() {
	viper.SetDefault("output", "table")
	viper.SetDefault("quiet", false)
	viper.SetDefault("fail_on", []string{})

	viper.SetDefault("ecosystems.npm.enabled", true)
	viper.SetDefault("ecosystems.pip.enabled", true)
	viper.SetDefault("ecosystems.cargo.enabled", true)
	viper.SetDefault("ecosystems.nuget.enabled", true)
	viper.SetDefault("ecosystems.maven.enabled", true)
	viper.SetDefault("ecosystems.gradle.enabled", true)

	viper.SetDefault("checks.dependency_age_days", 7)
	viper.SetDefault("checks.version_range_strictness", "conservative")
}

func Load() (*Config, error) {
	SetDefaults()

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
