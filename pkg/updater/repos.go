package updater

import (
	"slices"
	"strings"
)

// alpamonRepoURLs are the PackageCloud repositories .github/workflows/release.yml publishes the stable, rc and dev channels to.
// The trailing slash keeps one from matching another as a prefix; packagecloud always puts a path segment after the repo name.
var alpamonRepoURLs = []string{
	"packagecloud.io/alpacax/alpamon/",
	"packagecloud.io/alpacax/alpamon-latest/",
	"packagecloud.io/alpacax/alpamon-dev/",
}

// ContainsAlpamonRepo reports whether s names any alpamon channel repo, whatever alias the operator gave it.
func ContainsAlpamonRepo(s string) bool {
	return slices.ContainsFunc(alpamonRepoURLs, func(r string) bool { return strings.Contains(s, r) })
}
