package archiveopen

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MountID returns the Linux mount ID of an open descriptor.
func MountID(fd int) (uint64, error) {
	info, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", strconv.Itoa(fd)))
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(info), "\n") {
		if value, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			return strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		}
	}
	return 0, errors.New("descriptor mount ID unavailable")
}
