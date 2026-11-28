package runner

import (
	"bytes"
	"os"
	"strconv"
)

// Field 22 is the process start time in clock ticks since boot. The preceding
// comm field may contain spaces and closing parentheses.
func sudoProcessStart(pid int) uint64 {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0
	}
	fields := bytes.Fields(data[end+1:])
	if len(fields) < 20 {
		return 0
	}
	ticks, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil {
		return 0
	}
	return ticks
}
