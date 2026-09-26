//go:build !alpamon_release_keys

package updater

// releaseKeyBundle is empty in a default build. The pinned upgrade path
// refuses to run against an empty bundle, so a build made without the release
// key tag can still take legacy upgrades but never a pinned one.
var releaseKeyBundle []byte
