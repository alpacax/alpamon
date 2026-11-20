package user

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const archivePrefix = "/home/deleted_users/"

func (h *UserHandler) checkHomeOwner(username, home string, requestedUID uint64, serviceAccount bool) error {
	if !validHomeUsername(username) {
		return fmt.Errorf("invalid username %q", username)
	}
	path := filepath.Join(h.homeRoot, username)
	if !serviceAccount {
		path = home
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		if !serviceAccount {
			return fmt.Errorf("system_home_conflict: %s is a symlink; refusing to create the account", path)
		}
		info, err = os.Stat(path)
	}
	if err != nil {
		return fmt.Errorf("failed to stat home directory: %w", err)
	}
	uid, err := fileOwnerUID(info)
	if err != nil {
		return err
	}
	if uid != requestedUID {
		return fmt.Errorf("system_home_conflict: %s is owned by uid %d, not %d; refusing to create the account", path, uid, requestedUID)
	}
	return nil
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
