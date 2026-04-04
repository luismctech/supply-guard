package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/agents"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/engine"
	"github.com/AlbertoMZCruz/supply-guard/internal/report"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func getToolDefinitions() []toolDefinition {
	return []toolDefinition{
		{
			Name:        "scan",
			Description: "Scan a project directory for supply chain security threats. Returns findings with severity, location, and fix suggestions.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"directory": {
						"type": "string",
						"description": "Directory to scan (defaults to current working directory)"
					},
					"checks": {
						"type": "array",
						"items": {"type": "string"},
						"description": "Only run specific checks by ID (e.g. [\"SG001\",\"SG006\"]). Empty means all checks."
					},
					"format": {
						"type": "string",
						"enum": ["json", "markdown", "diff"],
						"description": "Output format (default: json)"
					}
				}
			}`),
		},
		{
			Name:        "explain_finding",
			Description: "Get a detailed explanation of a security check and why a specific finding matters, including real-world attack examples.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"required": ["check_id"],
				"properties": {
					"check_id": {
						"type": "string",
						"description": "Check ID (SG001-SG012)"
					},
					"package": {
						"type": "string",
						"description": "Optional package name for context-specific explanation"
					}
				}
			}`),
		},
		{
			Name:        "suggest_fix",
			Description: "Generate an actionable fix suggestion for a specific finding. Returns either a diff patch or step-by-step instructions.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"required": ["check_id"],
				"properties": {
					"check_id": {
						"type": "string",
						"description": "Check ID (SG001-SG012)"
					},
					"file": {
						"type": "string",
						"description": "File path where the finding was detected"
					},
					"package": {
						"type": "string",
						"description": "Package name (for dependency-related fixes)"
					},
					"ecosystem": {
						"type": "string",
						"description": "Ecosystem (npm, pip, cargo, maven, nuget)"
					}
				}
			}`),
		},
		{
			Name:        "list_checks",
			Description: "List all available security checks with their IDs, descriptions, and which ecosystems they apply to.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {}
			}`),
		},
		{
			Name:        "get_policy",
			Description: "Read the current SupplyGuard policy configuration for a directory, showing which checks are enabled and severity thresholds.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"directory": {
						"type": "string",
						"description": "Project directory (defaults to current working directory)"
					}
				}
			}`),
		},
		{
			Name:        "install_agent_files",
			Description: "Install AI agent integration files (Cursor rules, MCP configs, AGENTS.md, SKILL.md) into a project directory. Merges MCP configs non-destructively.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"directory": {
						"type": "string",
						"description": "Project directory (defaults to current working directory)"
					},
					"files": {
						"type": "array",
						"items": {
							"type": "string",
							"enum": ["cursor-rule", "cursor-mcp", "vscode-mcp", "agents-md", "skill-md"]
						},
						"description": "Specific files to install. Empty or omitted installs all."
					}
				}
			}`),
		},
	}
}

// RegisterAllTools registers all MCP tool handlers on the server.
func RegisterAllTools(s *Server) {
	defs := getToolDefinitions()
	handlers := map[string]ToolHandler{
		"scan":                handleScan,
		"explain_finding":     handleExplainFinding,
		"suggest_fix":         handleSuggestFix,
		"list_checks":         handleListChecks,
		"get_policy":          handleGetPolicy,
		"install_agent_files": handleInstallAgentFiles,
	}
	for _, d := range defs {
		if h, ok := handlers[d.Name]; ok {
			s.RegisterTool(d.Name, d.Description, d.InputSchema, h)
		}
	}
}

const errInvalidArgs = "invalid arguments: %w"

func handleScan(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Directory string   `json:"directory"`
		Checks    []string `json:"checks"`
		Format    string   `json:"format"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &params); err != nil {
			return "", fmt.Errorf(errInvalidArgs, err)
		}
	}

	dir := params.Directory
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("cannot get working directory: %w", err)
		}
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return "", fmt.Errorf("config error: %w", err)
	}
	cfg.Quiet = true

	if len(params.Checks) > 0 {
		allChecks := []string{"SG001", "SG002", "SG003", "SG004", "SG005", "SG006",
			"SG007", "SG008", "SG009", "SG010", "SG011", "SG012"}
		enabled := make(map[string]bool, len(params.Checks))
		for _, c := range params.Checks {
			enabled[strings.ToUpper(c)] = true
		}
		var disabled []string
		for _, c := range allChecks {
			if !enabled[c] {
				disabled = append(disabled, c)
			}
		}
		cfg.Checks.Disabled = disabled
	}

	eng := engine.New(cfg)
	result, err := eng.Scan(ctx, absDir)
	if err != nil {
		return "", fmt.Errorf("scan failed: %w", err)
	}

	for i := range result.Findings {
		result.Findings[i].Fingerprint = result.Findings[i].ComputeFingerprint()
	}
	report.EnrichWithFixes(result.Findings)

	format := params.Format
	if format == "" {
		format = "json"
	}
	reporter, err := report.Get(format)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := reporter.Report(&buf, result); err != nil {
		return "", fmt.Errorf("report error: %w", err)
	}
	return buf.String(), nil
}

func handleExplainFinding(_ context.Context, args json.RawMessage) (string, error) {
	var params struct {
		CheckID string `json:"check_id"`
		Package string `json:"package"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf(errInvalidArgs, err)
	}

	checkID := types.CheckID(strings.ToUpper(params.CheckID))
	desc, ok := types.CheckDescriptions[checkID]
	if !ok {
		return "", fmt.Errorf("unknown check ID: %s", params.CheckID)
	}

	explanation := explainCheck(checkID, desc, params.Package)
	return explanation, nil
}

func handleSuggestFix(_ context.Context, args json.RawMessage) (string, error) {
	var params struct {
		CheckID   string `json:"check_id"`
		File      string `json:"file"`
		Package   string `json:"package"`
		Ecosystem string `json:"ecosystem"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf(errInvalidArgs, err)
	}

	checkID := types.CheckID(strings.ToUpper(params.CheckID))
	if _, ok := types.CheckDescriptions[checkID]; !ok {
		return "", fmt.Errorf("unknown check ID: %s", params.CheckID)
	}

	fix := suggestFixForCheck(checkID, params.File, params.Package, params.Ecosystem)
	return fix, nil
}

func handleListChecks(_ context.Context, _ json.RawMessage) (string, error) {
	type checkInfo struct {
		ID          string   `json:"id"`
		Description string   `json:"description"`
		Ecosystems  []string `json:"ecosystems"`
	}

	checks := []checkInfo{
		{ID: "SG001", Description: "Lockfile integrity verification", Ecosystems: []string{"npm", "pip", "cargo"}},
		{ID: "SG002", Description: "Install script detection", Ecosystems: []string{"npm", "pip", "cargo"}},
		{ID: "SG003", Description: "Known malicious package/domain match (IOC)", Ecosystems: []string{"npm", "pip", "cargo", "maven", "nuget"}},
		{ID: "SG004", Description: "Dependency age check", Ecosystems: []string{"npm"}},
		{ID: "SG005", Description: "Phantom dependency detection", Ecosystems: []string{"npm"}},
		{ID: "SG006", Description: "Typosquatting detection", Ecosystems: []string{"npm", "pip", "cargo", "maven", "nuget"}},
		{ID: "SG007", Description: "Provenance verification", Ecosystems: []string{"npm", "pip", "cargo", "nuget", "ci"}},
		{ID: "SG008", Description: "Package manager config hardening", Ecosystems: []string{"npm", "pip"}},
		{ID: "SG009", Description: "GitHub Actions SHA pinning", Ecosystems: []string{"ci"}},
		{ID: "SG010", Description: "Network call detection in scripts", Ecosystems: []string{"npm", "pip", "cargo", "maven", "nuget"}},
		{ID: "SG011", Description: "Version range permissiveness", Ecosystems: []string{"npm", "pip", "cargo", "maven", "nuget"}},
		{ID: "SG012", Description: "Unsafe CI install commands", Ecosystems: []string{"ci"}},
	}

	data, err := json.MarshalIndent(checks, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func handleGetPolicy(_ context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Directory string `json:"directory"`
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &params)
	}

	cfg, err := config.Load()
	if err != nil {
		return "", fmt.Errorf("config error: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func handleInstallAgentFiles(_ context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Directory string   `json:"directory"`
		Files     []string `json:"files"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &params); err != nil {
			return "", fmt.Errorf(errInvalidArgs, err)
		}
	}

	dir := params.Directory
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("cannot get working directory: %w", err)
		}
	}

	var files []agents.FileSpec
	if len(params.Files) > 0 {
		files = agents.FilesForIDs(params.Files)
		if len(files) == 0 {
			return "", fmt.Errorf("no valid file IDs provided. Valid IDs: cursor-rule, cursor-mcp, vscode-mcp, agents-md, skill-md")
		}
	} else {
		files = agents.Registry
	}

	results, err := agents.Install(dir, files)
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
