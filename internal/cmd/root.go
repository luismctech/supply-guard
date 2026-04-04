package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "supply-guard",
	Short: "Supply chain security scanner",
	Long: `SupplyGuard detects what vulnerability scanners miss:
malicious packages, suspicious install scripts, typosquatting,
IOC matches, and policy violations.

Zero dependencies. Works offline. Complements Trivy/Grype/Snyk.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./supplyguard.yaml)")
	rootCmd.PersistentFlags().StringP("output", "o", "table", "output format: table, json, sarif, markdown, diff")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "suppress banners, warnings, and decorations (agent-friendly)")
	rootCmd.PersistentFlags().StringSlice("fail-on", []string{}, "fail with exit code 1 on these severities (e.g. critical,high)")

	_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
	_ = viper.BindPFlag("fail_on", rootCmd.PersistentFlags().Lookup("fail-on"))
}

func initConfig() {
	config.SetDefaults()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, ".config", "supplyguard"))
		}

		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: cannot get working directory:", err)
			return
		}
		viper.AddConfigPath(cwd)
		viper.SetConfigName("supplyguard")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("SUPPLYGUARD")
	viper.AutomaticEnv()

	_ = viper.ReadInConfig()
}

// WarnIfUntrustedConfig prints a warning when config was loaded from the scan
// target directory (a malicious repo could plant a supplyguard.yaml that
// disables all checks). Returns true if an untrusted config was detected.
func WarnIfUntrustedConfig(scanDir string) bool {
	if cfgFile != "" {
		return false
	}
	usedFile := viper.ConfigFileUsed()
	if usedFile == "" {
		return false
	}
	cfgDir := filepath.Dir(usedFile)
	absScan, err := filepath.Abs(scanDir)
	if err != nil {
		return false
	}
	absCfg, err := filepath.Abs(cfgDir)
	if err != nil {
		return false
	}
	if absCfg == absScan {
		if os.Getenv("SUPPLYGUARD_TRUST_PROJECT_CONFIG") == "true" {
			return false
		}
		fmt.Fprintf(os.Stderr,
			"⚠  Warning: config loaded from scan target (%s).\n"+
				"   A malicious repo could disable checks via this file.\n"+
				"   Use --config to specify a trusted config path, or set\n"+
				"   SUPPLYGUARD_TRUST_PROJECT_CONFIG=true to suppress this warning.\n\n",
			usedFile)
		return true
	}
	return false
}
