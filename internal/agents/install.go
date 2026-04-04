package agents

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type FileID string

const (
	CursorRule FileID = "cursor-rule"
	CursorMCP  FileID = "cursor-mcp"
	VSCodeMCP  FileID = "vscode-mcp"
	AgentsMD   FileID = "agents-md"
	SkillMD    FileID = "skill-md"
)

type FileSpec struct {
	ID          FileID
	Name        string
	RelPath     string
	Description string
	Tags        []string // "cursor", "vscode", "docs"
}

var Registry = []FileSpec{
	{ID: CursorRule, Name: "Cursor Rule", RelPath: ".cursor/rules/supply-guard.mdc", Description: "Auto-triggers scanning when editing dependency files", Tags: []string{"cursor"}},
	{ID: CursorMCP, Name: "Cursor MCP Config", RelPath: ".cursor/mcp.json", Description: "Registers SupplyGuard as MCP server in Cursor", Tags: []string{"cursor"}},
	{ID: VSCodeMCP, Name: "VS Code MCP Config", RelPath: ".vscode/mcp.json", Description: "Registers SupplyGuard as MCP server in VS Code / Copilot", Tags: []string{"vscode"}},
	{ID: AgentsMD, Name: "AGENTS.md", RelPath: "AGENTS.md", Description: "Agent instructions for Codex and GitHub Copilot", Tags: []string{"docs"}},
	{ID: SkillMD, Name: "SKILL.md", RelPath: "SKILL.md", Description: "Cursor skill definition for SupplyGuard", Tags: []string{"cursor", "docs"}},
}

type InstallResult struct {
	FileID  FileID `json:"file_id"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Status  string `json:"status"` // "created", "updated", "skipped"
	Message string `json:"message,omitempty"`
}

func FilesForTags(tags []string) []FileSpec {
	if len(tags) == 0 {
		return Registry
	}
	tagSet := make(map[string]bool, len(tags))
	for _, t := range tags {
		tagSet[t] = true
	}
	var matched []FileSpec
	for _, f := range Registry {
		for _, ft := range f.Tags {
			if tagSet[ft] {
				matched = append(matched, f)
				break
			}
		}
	}
	return matched
}

func FilesForIDs(ids []string) []FileSpec {
	idSet := make(map[FileID]bool, len(ids))
	for _, id := range ids {
		idSet[FileID(id)] = true
	}
	var matched []FileSpec
	for _, f := range Registry {
		if idSet[f.ID] {
			matched = append(matched, f)
		}
	}
	return matched
}

func Install(dir string, files []FileSpec) ([]InstallResult, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve path: %w", err)
	}

	var results []InstallResult
	for _, f := range files {
		r := installFile(absDir, f)
		results = append(results, r)
	}
	return results, nil
}

func installFile(dir string, spec FileSpec) InstallResult {
	target := filepath.Join(dir, spec.RelPath)

	switch spec.ID {
	case CursorMCP, VSCodeMCP:
		return installMCPConfig(target, spec)
	default:
		return installStaticFile(target, spec)
	}
}

func installStaticFile(target string, spec FileSpec) InstallResult {
	content := templateContent(spec.ID)

	if _, err := os.Stat(target); err == nil {
		return InstallResult{FileID: spec.ID, Name: spec.Name, Path: target, Status: "skipped", Message: "already exists"}
	}

	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return InstallResult{FileID: spec.ID, Name: spec.Name, Path: target, Status: "error", Message: err.Error()}
	}

	if err := os.WriteFile(target, []byte(content), 0644); err != nil {
		return InstallResult{FileID: spec.ID, Name: spec.Name, Path: target, Status: "error", Message: err.Error()}
	}

	return InstallResult{FileID: spec.ID, Name: spec.Name, Path: target, Status: "created"}
}

func installMCPConfig(target string, spec FileSpec) InstallResult {
	serverEntry := mcpServerEntry()

	existing, err := os.ReadFile(target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return InstallResult{FileID: spec.ID, Name: spec.Name, Path: target, Status: "error", Message: err.Error()}
	}

	var merged []byte

	if errors.Is(err, os.ErrNotExist) || len(existing) == 0 {
		merged, err = createMCPConfig(spec.ID, serverEntry)
	} else {
		merged, err = mergeMCPConfig(existing, spec.ID, serverEntry)
	}

	if err != nil {
		return InstallResult{FileID: spec.ID, Name: spec.Name, Path: target, Status: "error", Message: err.Error()}
	}

	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return InstallResult{FileID: spec.ID, Name: spec.Name, Path: target, Status: "error", Message: err.Error()}
	}

	if err := os.WriteFile(target, merged, 0644); err != nil {
		return InstallResult{FileID: spec.ID, Name: spec.Name, Path: target, Status: "error", Message: err.Error()}
	}

	if errors.Is(os.ErrNotExist, err) || len(existing) == 0 {
		return InstallResult{FileID: spec.ID, Name: spec.Name, Path: target, Status: "created"}
	}
	return InstallResult{FileID: spec.ID, Name: spec.Name, Path: target, Status: "updated"}
}

const serverName = "supply-guard"

func mcpServerEntry() map[string]any {
	return map[string]any{
		"command": serverName,
		"args":    []string{"mcp"},
	}
}

func createMCPConfig(id FileID, entry map[string]any) ([]byte, error) {
	var cfg map[string]any

	if id == VSCodeMCP {
		entryWithType := make(map[string]any)
		for k, v := range entry {
			entryWithType[k] = v
		}
		entryWithType["type"] = "stdio"
		cfg = map[string]any{
			"servers": map[string]any{
				"supply-guard": entryWithType,
			},
		}
	} else {
		cfg = map[string]any{
			"mcpServers": map[string]any{
				serverName: entry,
			},
		}
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func mergeMCPConfig(existing []byte, id FileID, entry map[string]any) ([]byte, error) {
	var cfg map[string]any
	if err := json.Unmarshal(existing, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON in existing config: %w", err)
	}

	key := "mcpServers"
	if id == VSCodeMCP {
		key = "servers"
		entryWithType := make(map[string]any)
		for k, v := range entry {
			entryWithType[k] = v
		}
		entryWithType["type"] = "stdio"
		entry = entryWithType
	}

	servers, ok := cfg[key].(map[string]any)
	if !ok {
		servers = make(map[string]any)
	}
	servers[serverName] = entry
	cfg[key] = servers

	return json.MarshalIndent(cfg, "", "  ")
}

func IsInstalled(dir string, spec FileSpec) bool {
	target := filepath.Join(dir, spec.RelPath)
	_, err := os.Stat(target)
	return err == nil
}
