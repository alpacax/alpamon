//go:build !windows

package commandcancel

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

type processStartReader struct {
	procRoot   string
	clockTicks func() (uint64, error)
	mu         sync.Mutex
	metadata   processStartMetadata
}

type processStartMetadata struct {
	bootMillis uint64
	clockTicks uint64
}

// Metadata errors cannot prove that the process is gone.
// Leave their OS errors out of the PID absence error chain.
type processStartMetadataError struct{ cause error }

func (e *processStartMetadataError) Error() string {
	return fmt.Sprintf("process start metadata unavailable: %v", e.cause)
}

func (r *processStartReader) startTime(pid int) (int64, error) {
	data, err := os.ReadFile(filepath.Join(r.procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	started, err := parseProcessStartTicks(data)
	if err != nil {
		return 0, err
	}
	metadata, err := r.loadMetadata()
	if err != nil {
		return 0, err
	}
	seconds := started / metadata.clockTicks
	if seconds > (math.MaxInt64-metadata.bootMillis)/1000 {
		return 0, fmt.Errorf("process %d start time overflows Unix milliseconds", pid)
	}
	elapsed := seconds*1000 + (started%metadata.clockTicks)*1000/metadata.clockTicks
	if elapsed > math.MaxInt64-metadata.bootMillis {
		return 0, fmt.Errorf("process %d start time overflows Unix milliseconds", pid)
	}
	return int64(metadata.bootMillis + elapsed), nil
}

func (r *processStartReader) loadMetadata() (processStartMetadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.metadata.clockTicks != 0 {
		return r.metadata, nil
	}
	data, err := os.ReadFile(filepath.Join(r.procRoot, "stat"))
	if err != nil {
		return processStartMetadata{}, &processStartMetadataError{cause: err}
	}
	bootMillis, err := parseBootMillis(data)
	if err != nil {
		return processStartMetadata{}, &processStartMetadataError{cause: err}
	}
	clockTicks, err := r.clockTicks()
	if err == nil && (clockTicks == 0 || clockTicks > math.MaxInt64/1000) {
		err = fmt.Errorf("invalid clock ticks %d", clockTicks)
	}
	if err != nil {
		return processStartMetadata{}, &processStartMetadataError{cause: err}
	}
	r.metadata = processStartMetadata{bootMillis: bootMillis, clockTicks: clockTicks}
	return r.metadata, nil
}

func parseProcessStartTicks(data []byte) (uint64, error) {
	open, close := bytes.IndexByte(data, '('), bytes.LastIndexByte(data, ')')
	if open < 1 || close <= open {
		return 0, fmt.Errorf("malformed process stat command")
	}
	pid, err := strconv.ParseUint(string(bytes.TrimSpace(data[:open])), 10, 64)
	if err != nil || pid == 0 {
		return 0, fmt.Errorf("malformed process stat PID")
	}
	fields := bytes.Fields(data[close+1:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("process stat lacks start time")
	}
	started, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid process start ticks: %w", err)
	}
	return started, nil
}

func parseBootMillis(data []byte) (uint64, error) {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) == 0 || string(fields[0]) != "btime" {
			continue
		}
		if len(fields) != 2 {
			return 0, fmt.Errorf("malformed kernel boot time")
		}
		boot, err := strconv.ParseUint(string(fields[1]), 10, 64)
		if err != nil || boot == 0 || boot > math.MaxInt64/1000 {
			return 0, fmt.Errorf("invalid kernel boot time")
		}
		return boot * 1000, nil
	}
	return 0, fmt.Errorf("kernel boot time is missing")
}
