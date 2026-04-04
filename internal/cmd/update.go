package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultIOCURL  = "https://raw.githubusercontent.com/supply-guard/supply-guard/main/data/iocs.json"
	maxResponseMiB = 10
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update IOC threat intelligence database",
	Long: `Downloads the latest IOC (Indicators of Compromise) database from
the SupplyGuard repository. The embedded IOCs work offline, but
this command fetches the latest threat data for up-to-date protection.`,
	RunE: runUpdate,
}

func init() {
	updateCmd.Flags().String("url", defaultIOCURL, "URL to fetch IOC database from")
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
	rawURL, _ := cmd.Flags().GetString("url")

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("only HTTPS URLs are allowed (got %s)", parsed.Scheme)
	}

	fmt.Println("  Fetching latest IOC database...")

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to non-HTTPS URL blocked: %s", req.URL)
			}
			return nil
		},
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return fmt.Errorf("failed to fetch IOCs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch IOCs: HTTP %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxResponseMiB*1024*1024)
	body, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("invalid IOC data: %w", err)
	}

	version, _ := raw["version"].(string)

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot find home directory: %w", err)
	}

	configDir := filepath.Join(home, ".config", "supplyguard")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("cannot create config directory: %w", err)
	}

	iocPath := filepath.Join(configDir, "iocs.json")
	if err := os.WriteFile(iocPath, body, 0644); err != nil {
		return fmt.Errorf("cannot write IOC file: %w", err)
	}

	fmt.Printf("  ✓ IOC database updated (version: %s)\n", version)
	fmt.Printf("    Saved to: %s\n", iocPath)

	return nil
}
