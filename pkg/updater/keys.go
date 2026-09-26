package updater

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// releaseKeyBundleTag is the build tag that compiles the release signing keys
// into the binary. Without it the bundle is empty and every pinned upgrade is
// refused; see keys_default.go and keys_release.go.
const releaseKeyBundleTag = "alpamon_release_keys"

// ErrNoTrustedKeys is returned when a pinned upgrade finds no signing key to
// verify against. It is a refusal, not a condition to work around: there is no
// unsigned fallback.
var ErrNoTrustedKeys = errors.New("no release signing keys are compiled into this build (built without the " + releaseKeyBundleTag + " tag)")

// Keyring is the set of OpenPGP public keys a release checksums file must be
// signed by. The production keyring is compiled into the binary and never
// fetched, so whoever can serve an artifact cannot also choose the key that
// vouches for it.
type Keyring struct {
	entities openpgp.EntityList
}

// ParseKeyring reads one or more ASCII-armored public key blocks. An empty
// input yields an empty keyring, which verification refuses.
func ParseKeyring(armored []byte) (*Keyring, error) {
	kr := &Keyring{}
	trimmed := bytes.TrimSpace(armored)
	r := bytes.NewReader(trimmed)
	blocks := 0
	for r.Len() > 0 {
		block, err := armor.Decode(r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode key block: %w", err)
		}
		if block.Type != openpgp.PublicKeyType {
			return nil, fmt.Errorf("unexpected armor block %q in key bundle", block.Type)
		}
		entities, err := openpgp.ReadKeyRing(block.Body)
		if err != nil {
			return nil, fmt.Errorf("read key block: %w", err)
		}
		kr.entities = append(kr.entities, entities...)
		blocks++
	}
	// A non-empty bundle with no armored block is corrupt, not empty.
	if len(trimmed) > 0 && blocks == 0 {
		return nil, errors.New("key bundle holds no armored public key block")
	}
	return kr, nil
}

// Len reports how many keys the keyring holds.
func (k *Keyring) Len() int {
	if k == nil {
		return 0
	}
	return len(k.entities)
}

// ReleaseKeyring returns the keyring compiled into this build. It is empty
// unless the binary was built with the release key bundle tag.
func ReleaseKeyring() (*Keyring, error) {
	return ParseKeyring(releaseKeyBundle)
}
