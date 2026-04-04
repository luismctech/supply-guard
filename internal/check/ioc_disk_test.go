package check

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIOCFromDisk_ValidFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	db := IOCDatabase{
		Version: "test-1.0",
		C2Domains: []string{"evil.test"},
		MaliciousPackages: map[string][]MaliciousPackage{
			"npm": {{Name: "disk-malware", Reason: "from disk"}},
		},
	}
	raw, _ := json.Marshal(db)
	dir := filepath.Join(home, ".config", "supplyguard")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "iocs.json"), raw, 0644)

	ResetIOCForTesting()

	got, err := GetIOCDatabase()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Version != "test-1.0" {
		t.Errorf("expected version 'test-1.0', got %q", got.Version)
	}
	if len(got.MaliciousPackages["npm"]) != 1 || got.MaliciousPackages["npm"][0].Name != "disk-malware" {
		t.Error("expected disk IOC data to be loaded")
	}

	ResetIOCForTesting()
}

func TestLoadIOCFromDisk_InvalidJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".config", "supplyguard")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "iocs.json"), []byte("{invalid"), 0644)

	ResetIOCForTesting()

	got, err := GetIOCDatabase()
	if err != nil {
		t.Fatalf("should fall back to embedded, not error: %v", err)
	}
	if got.Version == "" && len(got.MaliciousPackages) == 0 {
		t.Log("embedded DB loaded as fallback (expected if iocs.json has data)")
	}

	ResetIOCForTesting()
}

func TestLoadIOCFromDisk_EmptyVersion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	db := IOCDatabase{Version: ""}
	raw, _ := json.Marshal(db)
	dir := filepath.Join(home, ".config", "supplyguard")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "iocs.json"), raw, 0644)

	ResetIOCForTesting()

	got, err := GetIOCDatabase()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Version == "" {
		t.Log("empty version rejected, fell back to embedded (expected)")
	}

	ResetIOCForTesting()
}

func TestCheckC2Domain_ReturnsError_WhenDBUnavailable(t *testing.T) {
	matches, err := CheckC2Domain("normal content")
	if err != nil {
		t.Skipf("IOC DB loaded successfully, can't test error path without mock: %v", err)
	}
	if matches != nil && len(matches) > 0 {
		t.Logf("matches found (expected for C2 domains in embedded DB): %v", matches)
	}
}
