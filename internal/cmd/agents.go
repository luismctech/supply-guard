package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/AlbertoMZCruz/supply-guard/internal/agents"
	"github.com/AlbertoMZCruz/supply-guard/internal/ui"
)

var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Manage AI agent integration files",
	Long: `Install and manage agent guidance files for AI coding assistants.

Supported integrations:
  cursor-rule   Cursor rule (.cursor/rules/supply-guard.mdc)
  cursor-mcp    Cursor MCP config (.cursor/mcp.json)
  vscode-mcp    VS Code MCP config (.vscode/mcp.json)
  agents-md     AGENTS.md for Codex / GitHub Copilot
  skill-md      SKILL.md for Cursor skills`,
}

var (
	installCursor bool
	installVSCode bool
	installDocs   bool
	installAll    bool
)

var agentsInstallCmd = &cobra.Command{
	Use:   "install [directory]",
	Short: "Install agent integration files into a project",
	Long: `Install AI agent guidance files into the target project directory.

By default installs all files. Use flags to select specific integrations:
  --cursor    Cursor rule + MCP config
  --vscode    VS Code / Copilot MCP config
  --docs      AGENTS.md + SKILL.md
  --all       Everything (default)

Examples:
  supply-guard agents install                  # Install all in current directory
  supply-guard agents install /path/to/project # Install all in specific directory
  supply-guard agents install --cursor         # Only Cursor files
  supply-guard agents install --vscode --docs  # VS Code MCP + doc files`,
	Args:          cobra.MaximumNArgs(1),
	RunE:          runAgentsInstall,
	SilenceErrors: true,
	SilenceUsage:  true,
}

var agentsListCmd = &cobra.Command{
	Use:   "list [directory]",
	Short: "List available agent integrations and their install status",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runAgentsList,
}

func init() {
	agentsInstallCmd.Flags().BoolVar(&installCursor, "cursor", false, "install Cursor files (rule + MCP config)")
	agentsInstallCmd.Flags().BoolVar(&installVSCode, "vscode", false, "install VS Code / Copilot MCP config")
	agentsInstallCmd.Flags().BoolVar(&installDocs, "docs", false, "install AGENTS.md + SKILL.md")
	agentsInstallCmd.Flags().BoolVar(&installAll, "all", false, "install all integrations (default)")

	agentsCmd.AddCommand(agentsInstallCmd)
	agentsCmd.AddCommand(agentsListCmd)
	rootCmd.AddCommand(agentsCmd)
}

func runAgentsInstall(cmd *cobra.Command, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	files := resolveFiles()

	fmt.Printf("\n  %s\n", ui.Bold("🤖  SupplyGuard Agent Setup"))
	fmt.Printf("  %s\n\n", ui.Dim("Installing agent integration files..."))

	results, err := agents.Install(dir, files)
	if err != nil {
		return err
	}

	for _, r := range results {
		printInstallResult(r)
	}

	installed := 0
	for _, r := range results {
		if r.Status == "created" || r.Status == "updated" {
			installed++
		}
	}

	fmt.Println()
	if installed > 0 {
		fmt.Printf("  %s %d file(s) installed.\n", ui.BoldGreen("Done!"), installed)
	} else {
		fmt.Printf("  %s All files already installed.\n", ui.Dim("Done!"))
	}
	fmt.Println()

	return nil
}

func runAgentsList(cmd *cobra.Command, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	fmt.Printf("\n  %s\n\n", ui.Bold("🤖  SupplyGuard Agent Integrations"))

	for _, spec := range agents.Registry {
		installed := agents.IsInstalled(dir, spec)

		status := ui.Dim("not installed")
		icon := ui.Dim("○")
		if installed {
			status = ui.Success("installed")
			icon = ui.Success("✓")
		}

		fmt.Printf("  %s %-20s %s\n", icon, ui.Bold(spec.Name), status)
		fmt.Printf("    %s\n", ui.Dim(spec.Description))
		fmt.Printf("    %s %s\n\n", ui.Dim("Path:"), ui.Cyan(spec.RelPath))
	}

	fmt.Printf("  %s %s\n\n", ui.Dim("Install with:"), ui.Bold("supply-guard agents install"))

	return nil
}

func resolveFiles() []FileSpec {
	noFlagsSet := !installCursor && !installVSCode && !installDocs && !installAll

	if installAll || noFlagsSet {
		return agents.Registry
	}

	var tags []string
	if installCursor {
		tags = append(tags, "cursor")
	}
	if installVSCode {
		tags = append(tags, "vscode")
	}
	if installDocs {
		tags = append(tags, "docs")
	}
	return agents.FilesForTags(tags)
}

func printInstallResult(r agents.InstallResult) {
	switch r.Status {
	case "created":
		fmt.Printf("  %s %s\n    %s\n", ui.Success("✓"), r.Name, ui.Dim(r.Path))
	case "updated":
		fmt.Printf("  %s %s %s\n    %s\n", ui.Success("✓"), r.Name, ui.Dim("(updated)"), ui.Dim(r.Path))
	case "skipped":
		fmt.Printf("  %s %s %s\n", ui.Dim("○"), r.Name, ui.Dim("("+r.Message+")"))
	case "error":
		fmt.Printf("  %s %s %s\n", ui.Error("✖"), r.Name, ui.Warn(r.Message))
	}
}

type FileSpec = agents.FileSpec
