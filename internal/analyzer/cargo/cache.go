package cargo

import "path/filepath"

type cargoProjectFiles struct {
	dir  string
	deps []cargoDep
}

func loadCargoProjectFiles(dir string) *cargoProjectFiles {
	cf := &cargoProjectFiles{dir: dir}
	lockPath := filepath.Join(dir, "Cargo.lock")
	cf.deps = parseCargoLock(lockPath)
	return cf
}
