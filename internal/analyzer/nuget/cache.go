package nuget

type nugetProjectFiles struct {
	dir       string
	csprojMap map[string][]csprojPackageRef
}

func loadNuGetProjectFiles(dir string) *nugetProjectFiles {
	nf := &nugetProjectFiles{
		dir:       dir,
		csprojMap: make(map[string][]csprojPackageRef),
	}

	for _, path := range findCsprojFiles(dir) {
		refs := parseCsproj(path)
		if len(refs) > 0 {
			nf.csprojMap[path] = refs
		}
	}

	return nf
}
