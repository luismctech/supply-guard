package check

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/AlbertoMZCruz/supply-guard/data"
)

type IOCDatabase struct {
	Version                  string                              `json:"version"`
	MaliciousPackages        map[string][]MaliciousPackage       `json:"malicious_packages"`
	C2Domains                []string                            `json:"c2_domains"`
	CompromisedVersions      map[string]map[string][]string      `json:"compromised_versions"`
	SuspiciousMaintainerEmails []string                          `json:"suspicious_maintainer_emails"`
}

type MaliciousPackage struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Date   string `json:"date"`
	Ref    string `json:"ref,omitempty"`
}

var (
	iocDB     *IOCDatabase
	iocDBOnce sync.Once
	iocDBErr  error
)

// ResetIOCForTesting resets the IOC singleton so tests can exercise
// different loading paths. Must only be called from tests.
func ResetIOCForTesting() {
	iocDBOnce = sync.Once{}
	iocDB = nil
	iocDBErr = nil
}

func GetIOCDatabase() (*IOCDatabase, error) {
	iocDBOnce.Do(func() {
		iocDB = &IOCDatabase{}
		if loaded := loadIOCFromDisk(); loaded != nil {
			iocDB = loaded
			return
		}
		iocDBErr = json.Unmarshal(data.IOCsJSON, iocDB)
	})
	return iocDB, iocDBErr
}

func loadIOCFromDisk() *IOCDatabase {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	path := filepath.Join(home, ".config", "supplyguard", "iocs.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var db IOCDatabase
	if err := json.Unmarshal(raw, &db); err != nil {
		return nil
	}
	if db.Version == "" {
		return nil
	}
	return &db
}

func CheckPackageIOC(ecosystem, name, version string) (*MaliciousPackage, error) {
	db, err := GetIOCDatabase()
	if err != nil {
		return nil, fmt.Errorf("failed to load IOC database: %w", err)
	}

	packages, ok := db.MaliciousPackages[ecosystem]
	if ok {
		for _, mp := range packages {
			if strings.EqualFold(mp.Name, name) {
				return &mp, nil
			}
		}
	}

	if versions, ok := db.CompromisedVersions[ecosystem]; ok {
		if compromised, ok := versions[name]; ok {
			for _, cv := range compromised {
				if cv == version {
					return &MaliciousPackage{
						Name:   name,
						Reason: fmt.Sprintf("Known compromised version %s@%s", name, version),
					}, nil
				}
			}
		}
	}

	return nil, nil
}

// CheckMaintainerEmail checks if an email matches suspicious maintainer patterns.
// Patterns in the IOC database use the format "domain+context" (e.g. "@protonmail.com+npm-publish").
// The "+context" suffix is stripped and only the domain is matched.
func CheckMaintainerEmail(email string) (bool, string) {
	if email == "" {
		return false, ""
	}

	db, err := GetIOCDatabase()
	if err != nil || len(db.SuspiciousMaintainerEmails) == 0 {
		return false, ""
	}

	lower := strings.ToLower(email)
	for _, pattern := range db.SuspiciousMaintainerEmails {
		domain := pattern
		if idx := strings.Index(pattern, "+"); idx != -1 {
			domain = pattern[:idx]
		}
		domain = strings.ToLower(domain)

		if strings.Contains(lower, domain) {
			return true, pattern
		}
	}

	return false, ""
}

func CheckC2Domain(content string) ([]string, error) {
	db, err := GetIOCDatabase()
	if err != nil {
		return nil, fmt.Errorf("IOC database unavailable: %w", err)
	}

	var matches []string
	lower := strings.ToLower(content)
	for _, domain := range db.C2Domains {
		if strings.Contains(lower, domain) {
			matches = append(matches, domain)
		}
	}
	return matches, nil
}
