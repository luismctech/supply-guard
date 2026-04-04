package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/AlbertoMZCruz/supply-guard/internal/mcp"

	_ "github.com/AlbertoMZCruz/supply-guard/internal/analyzer/cargo"
	_ "github.com/AlbertoMZCruz/supply-guard/internal/analyzer/maven"
	_ "github.com/AlbertoMZCruz/supply-guard/internal/analyzer/npm"
	_ "github.com/AlbertoMZCruz/supply-guard/internal/analyzer/nuget"
	_ "github.com/AlbertoMZCruz/supply-guard/internal/analyzer/pip"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP server for AI agent integration",
	Long: `Start a Model Context Protocol (MCP) server over stdio.

The MCP server exposes SupplyGuard as typed tools that AI agents
(Cursor, Copilot, Codex, etc.) can call directly:

  Tools: scan, explain_finding, suggest_fix, list_checks, get_policy
  Resources: supplyguard://checks, supplyguard://policy/{dir}

Configure in your AI agent:
  {
    "mcpServers": {
      "supply-guard": {
        "command": "supply-guard",
        "args": ["mcp"]
      }
    }
  }`,
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		srv := mcp.NewServer()
		mcp.RegisterAllTools(srv)
		mcp.RegisterAllResources(srv)

		os.Stderr.Close()

		return srv.Run(ctx)
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
