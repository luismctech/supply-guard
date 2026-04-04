package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/AlbertoMZCruz/supply-guard/internal/ui"
	"github.com/AlbertoMZCruz/supply-guard/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s %s\n", ui.Bold("supply-guard"), ui.BoldCyan(version.Version))
		fmt.Printf("  %s  %s\n", ui.Dim("commit"), version.Commit)
		fmt.Printf("  %s   %s\n", ui.Dim("built"), version.Date)
		fmt.Printf("  %s      %s\n", ui.Dim("go"), runtime.Version())
		fmt.Printf("  %s %s/%s\n", ui.Dim("os/arch"), runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
