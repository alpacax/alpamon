package utils

import (
	"fmt"
	"os"
)

func GetFileInfo(info os.FileInfo, path string) (permString, permOctal, owner, group string, err error) {
	permString = FormatPermissions(info.Mode())
	permOctal = fmt.Sprintf("%o", info.Mode().Perm())
	// Windows does not support Unix UID/GID ownership.
	return permString, permOctal, "", "", nil
}
