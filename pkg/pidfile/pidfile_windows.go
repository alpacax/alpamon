package pidfile

import (
	"fmt"
	"syscall"

	"github.com/alpacax/alpamon/pkg/utils"
)

func FilePath(name string) string {
	return fmt.Sprintf(`%s\%s.pid`, utils.RunDir(), name)
}

// isProcess checks whether a process is running on Windows
// by attempting to open it with minimal access rights.
func isProcess(pid int) bool {
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	handle, err := syscall.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	_ = syscall.CloseHandle(handle)
	return true
}
