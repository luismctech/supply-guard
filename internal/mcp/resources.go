package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

// RegisterAllResources registers MCP resources on the server.
func RegisterAllResources(s *Server) {
	s.RegisterResource(
		"supplyguard://checks",
		"SupplyGuard Checks",
		"List of all available security checks with IDs and descriptions",
		"application/json",
		readChecksResource,
	)

	s.RegisterResource(
		"supplyguard://policy/{dir}",
		"SupplyGuard Policy",
		"Current policy configuration for the project",
		"application/json",
		readPolicyResource,
	)
}

func readChecksResource(_ context.Context, _ string) (string, error) {
	type checkEntry struct {
		ID          string `json:"id"`
		Description string `json:"description"`
	}

	ordered := []types.CheckID{
		types.CheckLockfileIntegrity, types.CheckInstallScripts, types.CheckIOCMatch,
		types.CheckDependencyAge, types.CheckPhantomDependency, types.CheckTyposquatting,
		types.CheckProvenance, types.CheckConfigHardening, types.CheckActionsPinning,
		types.CheckNetworkCalls, types.CheckVersionRange, types.CheckCIInstall,
	}

	entries := make([]checkEntry, 0, len(ordered))
	for _, id := range ordered {
		entries = append(entries, checkEntry{
			ID:          string(id),
			Description: types.CheckDescriptions[id],
		})
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}
	return string(data), nil
}

func readPolicyResource(_ context.Context, uri string) (string, error) {
	_ = strings.TrimPrefix(uri, "supplyguard://policy/")

	cfg, err := config.Load()
	if err != nil {
		return "", fmt.Errorf("config error: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}
	return string(data), nil
}
