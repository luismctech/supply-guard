package nuget

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestDetect_WithCsproj(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "MyApp.csproj"), []byte("<Project></Project>"), 0644)

	a := &NuGetAnalyzer{}
	if !a.Detect(dir) {
		t.Error("expected Detect to return true with .csproj")
	}
}

func TestDetect_WithoutDotnet(t *testing.T) {
	dir := t.TempDir()
	a := &NuGetAnalyzer{}
	if a.Detect(dir) {
		t.Error("expected Detect to return false without dotnet files")
	}
}

func TestCheckNuGetVersionPinning_Wildcard(t *testing.T) {
	dir := t.TempDir()
	csproj := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.*" />
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>`
	os.WriteFile(filepath.Join(dir, "App.csproj"), []byte(csproj), 0644)

	nf := loadNuGetProjectFiles(dir)
	findings := checkNuGetVersionPinningCached(nf, "conservative")
	found := false
	for _, f := range findings {
		if f.Package == "Newtonsoft.Json" && f.CheckID == types.CheckVersionRange {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for wildcard version in Newtonsoft.Json")
	}

	for _, f := range findings {
		if f.Package == "Serilog" {
			t.Error("Serilog has exact version and should not be flagged")
		}
	}
}

func TestParseCsproj(t *testing.T) {
	dir := t.TempDir()
	csproj := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Pkg1" Version="1.0.0" />
    <PackageReference Include="Pkg2" Version="2.0.0" />
  </ItemGroup>
</Project>`
	path := filepath.Join(dir, "Test.csproj")
	os.WriteFile(path, []byte(csproj), 0644)

	refs := parseCsproj(path)
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}
	if refs[0].Include != "Pkg1" || refs[0].Version != "1.0.0" {
		t.Errorf("unexpected first ref: %+v", refs[0])
	}
}
