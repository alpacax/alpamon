package common

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// UserLookupFunc resolves a user by name. It mirrors os/user.Lookup so the
// production default can be assigned directly, while tests inject a fake.
type UserLookupFunc func(name string) (*user.User, error)

// GroupLookupFunc resolves a group by name, mirroring os/user.LookupGroup.
type GroupLookupFunc func(name string) (*user.Group, error)

// DefaultUserLookup is the production user lookup backed by os/user.
//
// NOTE: the release binary is built with CGO_ENABLED=0 (see .goreleaser.yaml),
// so this uses the pure-Go resolver that reads only /etc/passwd—it does NOT
// consult NSS (nsswitch.conf). Local users (the provisioning target) resolve
// correctly, but names that exist only in LDAP/SSSD/AD are INVISIBLE here.
// Callers must not assume this lookup is authoritative for directory-backed
// names; ReconcileUserCreate adds a best-effort create-time net (a re-lookup
// for local TOCTOU races, plus an "already exists" output fallback for the
// NSS-backed case the resolver cannot see).
func DefaultUserLookup(name string) (*user.User, error) { return user.Lookup(name) }

// DefaultGroupLookup is the production group lookup backed by os/user. The same
// CGO_ENABLED=0 caveat as DefaultUserLookup applies (reads /etc/group only).
func DefaultGroupLookup(name string) (*user.Group, error) { return user.LookupGroup(name) }

// UserExists classifies a user lookup result:
//   - found=true            : the user is present (u is non-nil).
//   - found=false, err==nil : the user is definitively absent (UnknownUserError).
//   - found=false, err!=nil : the lookup itself failed (e.g. unreadable
//     /etc/passwd); the caller must fail loud rather than blind-create.
func UserExists(lookup UserLookupFunc, name string) (u *user.User, found bool, err error) {
	u, e := lookup(name)
	if e == nil {
		return u, true, nil
	}
	var notFound user.UnknownUserError
	if errors.As(e, &notFound) {
		return nil, false, nil
	}
	return nil, false, e
}

// GroupExists mirrors UserExists for groups (UnknownGroupError means absent).
func GroupExists(lookup GroupLookupFunc, name string) (g *user.Group, found bool, err error) {
	g, e := lookup(name)
	if e == nil {
		return g, true, nil
	}
	var notFound user.UnknownGroupError
	if errors.As(e, &notFound) {
		return nil, false, nil
	}
	return nil, false, e
}

// UserUIDConflictMessage is the single wording used whenever an existing user's
// uid differs from the requested one, so the up-front gate and the create-time
// secondary net surface identical, unambiguous drift messages.
func UserUIDConflictMessage(username string, existingUID, requestedUID uint64) string {
	return fmt.Sprintf(
		"user %q already exists with uid %d but provisioning requested uid %d; "+
			"refusing to modify an existing account",
		username, existingUID, requestedUID)
}

// GroupGIDConflictMessage mirrors UserUIDConflictMessage for groups.
func GroupGIDConflictMessage(groupname string, existingGID, requestedGID uint64) string {
	return fmt.Sprintf(
		"group %q already exists with gid %d but provisioning requested gid %d; "+
			"refusing to modify an existing group",
		groupname, existingGID, requestedGID)
}

// alreadyExists reports whether a create tool's output indicates that the
// REQUESTED entity (by name) already exists. It requires both the "already
// exists" phrase and the entity name so that a collision on a different entity
// sharing the requested numeric id—e.g. groupadd printing "GID '1001' already
// exists" when a differently-named group owns that gid—is NOT mistaken for the
// requested name existing (which would leave that name uncreated and break a
// later lookup/Demote by name). This is a locale-sensitive last resort—the
// executor runs commands with LANG=en_US.UTF-8—used only AFTER the lookup-based
// checks, never as the primary decision (E-16).
func alreadyExists(output, name string) bool {
	return strings.Contains(output, "already exists") && strings.Contains(output, name)
}

// ClassifyGroupForCreate is the shared idempotency gate for group creation, used
// by both standalone addgroup (group handler) and the RHEL primary-group ensure
// inside handleAddUser, so the two paths stay consistent (A-3). It decides,
// purely from a lookup, whether the caller should create the group:
//   - needCreate=false, code==0  : group present with the expected gid; skip create.
//   - needCreate=true,  code==0  : group absent; caller should create it (then
//     pass the result through ReconcileGroupCreate as the secondary net).
//   - needCreate=false, code!=0  : gid conflict, unparseable gid, or a lookup
//     that itself failed; caller returns (code, out, err) as-is.
func ClassifyGroupForCreate(lookup GroupLookupFunc, groupname string, wantGID uint64) (needCreate bool, code int, out string, err error) {
	existing, groupExists, lookupErr := GroupExists(lookup, groupname)
	if lookupErr != nil {
		// Cannot confirm current state; do not blind-create over a possibly
		// shadowed entry. Fail loud so the drift is visible.
		return false, 1, fmt.Sprintf("unable to verify whether group %q exists: %v", groupname, lookupErr), lookupErr
	}
	if !groupExists {
		return true, 0, "", nil
	}
	gotGID, perr := strconv.ParseUint(existing.Gid, 10, 64)
	if perr != nil {
		return false, 1, fmt.Sprintf("group %q exists but its gid %q is not a valid number; refusing to modify an existing group", groupname, existing.Gid), nil
	}
	if gotGID != wantGID {
		return false, 1, GroupGIDConflictMessage(groupname, gotGID, wantGID), nil
	}
	return false, 0, "", nil
}

// ReconcileUserCreate is the create-time secondary net for adduser/useradd.
//
// The primary idempotency decision is made by an up-front UserExists gate. This
// net covers the two cases the gate cannot: a concurrent provisioner that
// created the user between the gate and the create call (TOCTOU), and—because
// the CGO_ENABLED=0 resolver cannot see NSS/LDAP/SSSD names—a directory-backed
// account the gate reported absent. On a non-zero create result:
//   - re-lookup finds the user with a matching (or omitted, uidRequested=false)
//     uid -> idempotent success (0, "", nil).
//   - re-lookup finds the user with a DIFFERENT uid -> surface a conflict.
//   - re-lookup still cannot see the user BUT the create tool (which is
//     NSS-aware) reported "already exists" -> tolerate as idempotent success.
//     Identity cannot be verified here, so this is a best-effort last resort.
//   - otherwise -> return the original create failure unchanged.
//
// When code == 0 it is a no-op that returns the inputs untouched, so callers can
// wrap every create unconditionally without affecting the success path.
func ReconcileUserCreate(
	lookup UserLookupFunc, username string, wantUID uint64, uidRequested bool,
	code int, out string, cmdErr error,
) (int, string, error) {
	if code == 0 {
		return code, out, cmdErr
	}
	if existing, found, lookupErr := UserExists(lookup, username); lookupErr == nil && found {
		if uidRequested {
			gotUID, perr := strconv.ParseUint(existing.Uid, 10, 64)
			if perr != nil {
				return code, out, cmdErr // cannot verify identity; surface original failure
			}
			if gotUID != wantUID {
				return 1, UserUIDConflictMessage(username, gotUID, wantUID), nil
			}
		}
		log.Info().
			Str("username", username).
			Msg("Create returned non-zero but the user is already present with the expected identity; treating as idempotent success")
		return 0, "", nil
	}
	// Tertiary net: invisible to the pure-Go resolver but the NSS-aware create
	// tool says this NAME already exists (LDAP/SSSD-backed). Tolerate, since
	// failing here would reintroduce the #344 breakage; identity is unverifiable.
	// A collision on a different account sharing the uid is not tolerated here
	// (alreadyExists requires the username in the output).
	if alreadyExists(out, username) {
		log.Warn().
			Str("username", username).
			Str("output", out).
			Msg("Create reported the user already exists but it is invisible to the pure-Go resolver (likely NSS/LDAP/SSSD-backed); treating as idempotent (identity unverifiable)")
		return 0, "", nil
	}
	return code, out, cmdErr
}

// ReconcileGroupCreate is the create-time secondary net for addgroup/groupadd,
// mirroring ReconcileUserCreate. A group has no "omitted gid" case in the
// provisioning payloads (GID is validated required,min=1), so the gid is always
// compared when the group is visible. The "already exists" tertiary net tolerates
// only a same-name collision (NSS-backed group); a gid-in-use collision by a
// differently-named group is surfaced, since the requested name stays uncreated.
func ReconcileGroupCreate(
	lookup GroupLookupFunc, groupname string, wantGID uint64,
	code int, out string, cmdErr error,
) (int, string, error) {
	if code == 0 {
		return code, out, cmdErr
	}
	if existing, found, lookupErr := GroupExists(lookup, groupname); lookupErr == nil && found {
		gotGID, perr := strconv.ParseUint(existing.Gid, 10, 64)
		if perr != nil {
			return code, out, cmdErr
		}
		if gotGID != wantGID {
			return 1, GroupGIDConflictMessage(groupname, gotGID, wantGID), nil
		}
		log.Info().
			Str("groupname", groupname).
			Msg("Create returned non-zero but the group is already present with the expected gid; treating as idempotent success")
		return 0, "", nil
	}
	// Tertiary net: tolerate only when the output names THIS group (NSS-backed
	// same-name group invisible to the pure-Go resolver). A "GID already exists"
	// collision by a differently-named group is not tolerated—the requested
	// name would remain uncreated—so it falls through to the original failure.
	if alreadyExists(out, groupname) {
		log.Warn().
			Str("groupname", groupname).
			Str("output", out).
			Msg("Create reported the group already exists but it is invisible to the pure-Go resolver (likely NSS-backed); treating as idempotent (identity unverifiable)")
		return 0, "", nil
	}
	return code, out, cmdErr
}
