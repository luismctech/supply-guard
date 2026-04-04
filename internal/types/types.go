package types

import (
	"crypto/sha256"
	"fmt"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type CheckID string

const (
	CheckLockfileIntegrity  CheckID = "SG001"
	CheckInstallScripts     CheckID = "SG002"
	CheckIOCMatch           CheckID = "SG003"
	CheckDependencyAge      CheckID = "SG004"
	CheckPhantomDependency  CheckID = "SG005"
	CheckTyposquatting      CheckID = "SG006"
	CheckProvenance         CheckID = "SG007"
	CheckConfigHardening    CheckID = "SG008"
	CheckActionsPinning     CheckID = "SG009"
	CheckNetworkCalls       CheckID = "SG010"
	CheckVersionRange       CheckID = "SG011"
	CheckCIInstall          CheckID = "SG012"
)

var CheckDescriptions = map[CheckID]string{
	CheckLockfileIntegrity:  "Lockfile integrity verification",
	CheckInstallScripts:     "Install script detection",
	CheckIOCMatch:           "Known malicious package/domain match",
	CheckDependencyAge:      "Dependency age check",
	CheckPhantomDependency:  "Phantom dependency detection",
	CheckTyposquatting:      "Typosquatting detection",
	CheckProvenance:         "Provenance verification",
	CheckConfigHardening:    "Package manager config hardening",
	CheckActionsPinning:     "GitHub Actions SHA pinning",
	CheckNetworkCalls:       "Network call detection in scripts",
	CheckVersionRange:       "Version range permissiveness",
	CheckCIInstall:          "Unsafe CI install commands",
}

// FixSuggestion provides a machine-actionable fix that AI agents can auto-apply.
type FixSuggestion struct {
	Type        string `json:"type"`                  // "replace", "delete", "add", "config_change", "command"
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	OldContent  string `json:"old_content,omitempty"`
	NewContent  string `json:"new_content,omitempty"`
	Description string `json:"description,omitempty"` // human/AI-readable when fix isn't deterministic
}

type Finding struct {
	CheckID     CheckID         `json:"check_id"`
	Severity    Severity        `json:"severity"`
	Ecosystem   string          `json:"ecosystem"`
	Package     string          `json:"package,omitempty"`
	Version     string          `json:"version,omitempty"`
	File        string          `json:"file"`
	Line        int             `json:"line,omitempty"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Remediation string          `json:"remediation,omitempty"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Fix         *FixSuggestion  `json:"fix,omitempty"`
}

// ComputeFingerprint generates a stable hash for deduplication across scans.
func (f *Finding) ComputeFingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s", f.CheckID, f.File, f.Package, f.Version)
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

type ScanResult struct {
	ProjectDir string    `json:"project_dir"`
	Timestamp  time.Time `json:"timestamp"`
	Duration   string    `json:"duration"`
	Ecosystems []string  `json:"ecosystems_detected"`
	Summary    Summary   `json:"summary"`
	Findings   []Finding `json:"findings"`
}

type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func (s *Summary) Add(sev Severity) {
	s.Total++
	switch sev {
	case SeverityCritical:
		s.Critical++
	case SeverityHigh:
		s.High++
	case SeverityMedium:
		s.Medium++
	case SeverityLow:
		s.Low++
	case SeverityInfo:
		s.Info++
	}
}

func (s *Summary) HasSeverity(sevs ...Severity) bool {
	for _, sev := range sevs {
		switch sev {
		case SeverityCritical:
			if s.Critical > 0 {
				return true
			}
		case SeverityHigh:
			if s.High > 0 {
				return true
			}
		case SeverityMedium:
			if s.Medium > 0 {
				return true
			}
		case SeverityLow:
			if s.Low > 0 {
				return true
			}
		case SeverityInfo:
			if s.Info > 0 {
				return true
			}
		}
	}
	return false
}
