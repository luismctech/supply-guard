package maven

import (
	"encoding/xml"
	"path/filepath"

	"github.com/AlbertoMZCruz/supply-guard/internal/safefile"
)

type mavenProjectFiles struct {
	dir      string
	pom      *pomFile
	hasPom   bool
}

func loadMavenProjectFiles(dir string) *mavenProjectFiles {
	mf := &mavenProjectFiles{dir: dir}

	pomPath := filepath.Join(dir, "pom.xml")
	if data, err := safefile.ReadFile(pomPath); err == nil {
		var pom pomFile
		if xml.Unmarshal(data, &pom) == nil {
			mf.pom = &pom
			mf.hasPom = true
		}
	}

	return mf
}
