package user

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

const archivePrefix = "/home/deleted_users/"

var homeScanSlot = make(chan struct{}, 1)

type homeRootIdentity struct {
	info    os.FileInfo
	mountID uint64
}

type homeScanResult struct {
	owners map[uint64]string
	target os.FileInfo
	err    error
}

func checkHomeOwner(path string, info os.FileInfo, requestedUID uint64) error {
	if info == nil {
		return nil
	}
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
	return nil
}

func (h *UserHandler) homeOwners(ctx context.Context, path, configuredRoot string, includeTarget bool) homeScanResult {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case homeScanSlot <- struct{}{}:
	default:
		return homeScanResult{err: errors.New("a previous home ownership scan is still running")}
	}
	root, scan := h.homeRoot, h.scanHomeOwners
	result := make(chan homeScanResult, 1)
	go func() {
		r := scan(ctx, path, root, configuredRoot, includeTarget)
		<-homeScanSlot
		result <- r
	}()
	select {
	case r := <-result:
		if ctx.Err() == nil {
			return r
		}
	case <-ctx.Done():
	}
	return homeScanResult{err: fmt.Errorf("cannot verify home ownership: %w", ctx.Err())}
}

func scanHomeOwners(ctx context.Context, path, homeRoot, configuredRoot string, includeTarget bool) homeScanResult {
	target, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return homeScanResult{err: fmt.Errorf("failed to stat home directory: %w", err)}
	}
	owners := make(map[uint64]string)
	var seen []homeRootIdentity
	for _, root := range []string{filepath.Dir(path), homeRoot, configuredRoot} {
		if err := scanHomeRoot(ctx, root, target, includeTarget, &seen, owners); err != nil {
			return homeScanResult{err: fmt.Errorf("failed to scan home root %s: %w", root, err)}
		}
	}
	current, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return homeScanResult{err: fmt.Errorf("failed to recheck home directory: %w", err)}
	}
	if (current != nil || target != nil) && (current == nil || target == nil || !os.SameFile(current, target)) {
		return homeScanResult{err: fmt.Errorf("system_home_conflict: %s changed during the scan", path)}
	}
	return homeScanResult{owners: owners, target: current}
}

func scanHomeRoot(ctx context.Context, root string, target os.FileInfo, includeTarget bool, seen *[]homeRootIdentity, owners map[uint64]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	opened, err := os.OpenRoot(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = opened.Close() }()
	dir, err := opened.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	mountID, err := homeRootMountID(dir)
	if err == nil {
		for _, prior := range *seen {
			if prior.mountID == mountID && os.SameFile(prior.info, info) {
				return nil
			}
		}
		*seen = append(*seen, homeRootIdentity{info: info, mountID: mountID})
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := dir.ReadDir(64)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if !info.IsDir() || (!includeTarget && target != nil && os.SameFile(info, target)) {
				continue
			}
			uid, err := fileOwnerUID(info)
			if err != nil {
				return err
			}
			owners[uid] = filepath.Join(root, entry.Name())
		}
	}
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
	// Only UIDs inside the regular range compete; system IDs and nobody (65534) do not.
	highest := minUID - 1
	for uid := range owners {
		if uid >= minUID && uid <= maxUID {
			highest = max(highest, uid)
		}
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
		if uid >= minUID && uid <= maxUID {
			highest = max(highest, uid)
		}
	}
	if highest >= maxUID {
		return 0, fmt.Errorf("no service account UID available above %d within range %d to %d", highest, minUID, maxUID)
	}
	return highest + 1, nil
}
