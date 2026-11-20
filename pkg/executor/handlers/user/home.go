package user

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const archivePrefix = "/home/deleted_users/"

func (h *UserHandler) checkHomeOwner(username string, requestedUID uint64) error {
	if !validHomeUsername(username) {
		return fmt.Errorf("invalid username %q", username)
	}
	path := filepath.Join(h.homeRoot, username)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
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
		return fmt.Errorf("system_home_conflict: %s is owned by uid %d, not %d; refusing to create the account", "/home/"+username, uid, requestedUID)
	}
	return nil
}

func validHomeUsername(username string) bool {
	return username != "" && username != "." && username != ".." && !strings.ContainsAny(username, "/\\\x00")
}

func (h *UserHandler) archiveDestination(username, archiveTo string) (string, error) {
	stamp, ok := strings.CutPrefix(archiveTo, archivePrefix+username+"_")
	if !validHomeUsername(username) || !ok || !strings.HasSuffix(stamp, "Z") {
		return "", fmt.Errorf("invalid_archive_path: expected %s%s_<RFC3339 UTC timestamp ending in Z>", archivePrefix, username)
	}
	if _, err := time.Parse(time.RFC3339, stamp); err != nil {
		return "", fmt.Errorf("invalid_archive_path: invalid RFC3339 timestamp: %w", err)
	}

	path := filepath.Join(h.homeRoot, "deleted_users", username+"_"+stamp)
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("invalid_archive_path: %s already exists", archiveTo)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("invalid_archive_path: cannot check destination: %w", err)
	}
	return path, nil
}

func (h *UserHandler) backupHomeDirectory(home, destination string, uid int) (bool, error) {
	if home == "" {
		return false, nil
	}
	info, err := os.Lstat(home)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to stat home directory: %w", err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("home path %s is not a directory", home)
	}

	parent := filepath.Dir(destination)
	if err := os.Mkdir(parent, 0700); err == nil {
		if _, err := h.chownHome(parent, 0, 0, -1); err != nil {
			return false, fmt.Errorf("failed to set archive parent ownership: %w", err)
		}
	} else if !errors.Is(err, os.ErrExist) {
		return false, fmt.Errorf("failed to create archive parent: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return false, fmt.Errorf("failed to stat archive parent: %w", err)
	}
	owner, err := fileOwnerUID(parentInfo)
	if err != nil {
		return false, err
	}
	if !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0700 || owner != uint64(os.Geteuid()) {
		return false, fmt.Errorf("unsafe archive parent %s: expected a private directory owned by the agent", parent)
	}

	if err := renameHome(home, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, fmt.Errorf("invalid_archive_path: %s already exists", destination)
		}
		if errors.Is(err, os.ErrNotExist) {
			if _, statErr := os.Lstat(home); errors.Is(statErr, os.ErrNotExist) {
				return false, nil
			}
		}
		return false, fmt.Errorf("failed to move home directory: %w", err)
	}

	info, err = os.Lstat(destination)
	if err != nil {
		return false, fmt.Errorf("failed to stat archived directory: %w", err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("archive path %s is not a directory", destination)
	}
	skipped, err := h.chownHome(destination, 0, 0, uid)
	if err != nil {
		return false, fmt.Errorf("failed to chown archived directory: %w", err)
	}
	if err := os.Chmod(destination, 0700); err != nil {
		return false, fmt.Errorf("failed to chmod archived directory: %w", err)
	}

	log.Info().Str("archiveDir", destination).Int("hardLinksLeftUnchanged", skipped).Msg("Home directory archived")
	return true, nil
}
