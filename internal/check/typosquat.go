package check

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/AlbertoMZCruz/supply-guard/data"
)

type PopularPackages struct {
	Npm   []string `json:"npm"`
	Pip   []string `json:"pip"`
	Cargo []string `json:"cargo"`
	Nuget []string `json:"nuget"`
	Maven []string `json:"maven"`
}

type popularEntry struct {
	original string
	lower    string
}

var (
	popularPkgs     *PopularPackages
	popularPkgsOnce sync.Once
	popularPkgsErr  error
	lowerCache      map[string][]popularEntry
)

func getPopularPackages() (*PopularPackages, error) {
	popularPkgsOnce.Do(func() {
		popularPkgs = &PopularPackages{}
		popularPkgsErr = json.Unmarshal(data.PopularPackagesJSON, popularPkgs)
		if popularPkgsErr != nil {
			return
		}
		lowerCache = map[string][]popularEntry{
			"npm":   precomputeLower(popularPkgs.Npm),
			"pip":   precomputeLower(popularPkgs.Pip),
			"cargo": precomputeLower(popularPkgs.Cargo),
			"nuget": precomputeLower(popularPkgs.Nuget),
			"maven": precomputeLower(popularPkgs.Maven),
		}
	})
	return popularPkgs, popularPkgsErr
}

func precomputeLower(list []string) []popularEntry {
	entries := make([]popularEntry, len(list))
	for i, s := range list {
		entries[i] = popularEntry{original: s, lower: strings.ToLower(s)}
	}
	return entries
}

// CheckTyposquatting checks if a package name is suspiciously similar to a popular package.
func CheckTyposquatting(ecosystem, name string, maxDistance int) (string, int, error) {
	if _, err := getPopularPackages(); err != nil {
		return "", 0, err
	}

	entries, ok := lowerCache[ecosystem]
	if !ok {
		return "", 0, nil
	}

	lowerName := strings.ToLower(name)
	lenName := len(lowerName)

	for _, e := range entries {
		if lowerName == e.lower {
			return "", 0, nil
		}
		lenDiff := len(e.lower) - lenName
		if lenDiff > maxDistance || lenDiff < -maxDistance {
			continue
		}
		dist := levenshtein(lowerName, e.lower)
		if dist > 0 && dist <= maxDistance {
			return e.original, dist, nil
		}
	}

	return "", 0, nil
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)

	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}
