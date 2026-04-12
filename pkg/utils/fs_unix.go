//go:build !windows

package utils

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func GetFileInfo(info os.FileInfo, path string) (permString, permOctal, owner, group string, err error) {
	permString = FormatPermissions(info.Mode())
	permOctal = fmt.Sprintf("%o", info.Mode().Perm())

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", "", "", "", fmt.Errorf("failed to get system stat information")
	}

	uidStr := strconv.Itoa(int(stat.Uid))
	gidStr := strconv.Itoa(int(stat.Gid))

	ownerInfo, err := user.LookupId(uidStr)
	if err != nil {
		return "", "", "", "", err
	}
	groupInfo, err := user.LookupGroupId(gidStr)
	if err != nil {
		return "", "", "", "", err
	}

	return permString, permOctal, ownerInfo.Username, groupInfo.Name, nil
}
