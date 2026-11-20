package user

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

const archivePrefix = "/home/deleted_users/"

func (h *UserHandler) checkHomeOwner(home string, requestedUID uint64) error {
	path := home
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("system_home_conflict: %s is a symlink; refusing to create the account", path)
		}
		if !info.IsDir() {
			return fmt.Errorf("system_home_conflict: %s is not a directory", path)
		}
		uid, err := fileOwnerUID(info)
		if err != nil {
			return err
		}
		if uid != requestedUID {
			return fmt.Errorf("system_home_conflict: %s is owned by uid %d, not %d; refusing to create the account", path, uid, requestedUID)
		}
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("failed to stat home directory: %w", err)
	}

	return nil
}

func (h *UserHandler) homeOwners(path, configuredRoot string, includeTarget bool) (map[uint64]string, error) {
	owners := make(map[uint64]string)
	seen := make(map[string]bool)
	// Scan the target parent first so aliases of it cannot count the target twice.
	for _, candidate := range []string{filepath.Dir(path), h.homeRoot, configuredRoot} {
		root, err := filepath.EvalSymlinks(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to resolve home root %s: %w", candidate, err)
		}
		if seen[root] {
			continue
		}
		seen[root] = true
		entries, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list home directories: %w", err)
		}
		for _, entry := range entries {
			child := filepath.Join(candidate, entry.Name())
			if !entry.IsDir() || (!includeTarget && child == path) {
				continue
			}
			info, err := entry.Info()
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("failed to stat home directory: %w", err)
			}
			uid, err := fileOwnerUID(info)
			if err != nil {
				return nil, err
			}
			owners[uid] = child
		}
	}
	return owners, nil
}

func (h *UserHandler) defaultHomeRoot() (string, error) {
	path, key := "/etc/default/useradd", "HOME"
	if utils.PlatformLike == "debian" {
		path, key = "/etc/adduser.conf", "DHOME"
	}
	data, err := h.readAccountFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return h.homeRoot, nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", path, err)
	}
	root := h.homeRoot
	for line := range strings.SplitSeq(string(data), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) != key {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == 39) && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if !filepath.IsAbs(value) {
			return "", fmt.Errorf("invalid %s in %s: expected an absolute home root", key, path)
		}
		root = filepath.Clean(value)
	}
	return root, nil
}

func validHomeUsername(username string) bool {
	return username != "" && username != "." && username != ".." && !strings.ContainsAny(username, "/\\\x00")
}

func archiveDestination(username, archiveTo string) (string, error) {
	stamp, ok := strings.CutPrefix(archiveTo, archivePrefix+username+"_")
	if !validHomeUsername(username) || !ok || !strings.HasSuffix(stamp, "Z") {
		return "", fmt.Errorf("invalid_archive_path: expected %s%s_<RFC3339 UTC timestamp ending in Z>", archivePrefix, username)
	}
	if _, err := time.Parse(time.RFC3339, stamp); err != nil {
		return "", fmt.Errorf("invalid_archive_path: invalid RFC3339 timestamp: %w", err)
	}

	return username + "_" + stamp, nil
}

func archivedDeleteFailure(destination string, cause error) error {
	return fmt.Errorf("account_delete_failed: home archived to %s; %w", destination, cause)
}

func parseUIDBounds(data []byte) (uint64, uint64) {
	minUID, maxUID := uint64(1000), uint64(60000)
	seen := make(map[string]bool)
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) < 2 || seen[fields[0]] {
			continue
		}
		key := fields[0]
		if key != "UID_MIN" && key != "UID_MAX" {
			continue
		}
		seen[key] = true
		uid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil || uid == 0 {
			continue
		}
		if key == "UID_MIN" {
			minUID = uid
		} else {
			maxUID = uid
		}
	}
	return minUID, maxUID
}

func (h *UserHandler) nextServiceUID(owners map[uint64]string) (uint64, error) {
	defs, err := h.readAccountFile("/etc/login.defs")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("reading UID bounds: %w", err)
	}
	minUID, maxUID := parseUIDBounds(defs)
	var highest uint64
	for uid := range owners {
		highest = max(highest, uid)
	}
	passwd, err := h.readAccountFile("/etc/passwd")
	if err != nil {
		return 0, fmt.Errorf("reading passwd: %w", err)
	}
	for line := range strings.SplitSeq(string(passwd), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return 0, fmt.Errorf("invalid passwd entry")
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid passwd UID: %w", err)
		}
		highest = max(highest, uid)
	}
	if highest >= maxUID || highest+1 < minUID {
		return 0, fmt.Errorf("no service account UID available above %d within range %d to %d", highest, minUID, maxUID)
	}
	return highest + 1, nil
}
