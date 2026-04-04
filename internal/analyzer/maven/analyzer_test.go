package maven

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestDetect_WithPomXml(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project></project>"), 0644)

	a := &MavenAnalyzer{}
	if !a.Detect(dir) {
		t.Error("expected Detect to return true with pom.xml")
	}
}

func TestDetect_WithBuildGradle(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "build.gradle"), []byte("plugins {}"), 0644)

	a := &MavenAnalyzer{}
	if !a.Detect(dir) {
		t.Error("expected Detect to return true with build.gradle")
	}
}

func TestAnalyzeMaven_HTTPRepository(t *testing.T) {
	dir := t.TempDir()
	pom := `<project>
  <repositories>
    <repository>
      <id>insecure</id>
      <url>http://repo.example.com/maven2</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>`
	os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0644)

	mf := loadMavenProjectFiles(dir)
	findings := analyzeMavenPom(mf)
	found := false
	for _, f := range findings {
		if f.CheckID == types.CheckConfigHardening && f.Severity == types.SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for HTTP repository")
	}
}

func TestAnalyzeGradle_MissingVerification(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "build.gradle"), []byte("dependencies {}"), 0644)

	findings := analyzeGradle(dir)
	found := false
	for _, f := range findings {
		if f.Title == "Gradle verification-metadata.xml not found" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for missing verification-metadata.xml")
	}
}
