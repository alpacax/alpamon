//go:build alpamon_release_keys

package updater

import _ "embed"

// releaseKeyBundle holds the public half of the release signing keys. The file
// is committed alongside the release that first ships it; building with the tag
// before it exists fails, which is the intended behavior.
//
//go:embed release-keys/alpamon-release-keys.asc
var releaseKeyBundle []byte
