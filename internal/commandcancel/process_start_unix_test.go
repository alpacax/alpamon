//go:build !windows

package commandcancel

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const processStatFixture = "42 (sleep) S 1 42 42 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 250 4096 1\n"

func startReaderFixture(t *testing.T, hz uint64) *processStartReader {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "42"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "42", "stat"), []byte(processStatFixture), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "stat"), []byte("cpu 1 2 3\nbtime 1700000000\n"), 0600))
	return &processStartReader{procRoot: root, clockTicks: func() (uint64, error) { return hz, nil }}
}

func TestProcessStartReaderUsesClockTicks(t *testing.T) {
	for _, tc := range []struct {
		hz   uint64
		want int64
	}{
		{100, 1700000002500},
		{250, 1700000001000},
		{1024, 1700000000244},
	} {
		reader := startReaderFixture(t, tc.hz)
		started, err := reader.startTime(42)
		require.NoError(t, err)
		assert.Equal(t, tc.want, started)
	}
}

func TestProcessStartReaderKeepsItsCapturedBootTime(t *testing.T) {
	reader := startReaderFixture(t, 100)
	first, err := reader.startTime(42)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(reader.procRoot, "stat"), []byte("btime 1700000001\n"), 0600))
	second, err := reader.startTime(42)
	require.NoError(t, err)
	assert.Equal(t, int64(1700000002500), first)
	assert.Equal(t, first, second)
}

func TestProcessStartReaderSharesFirstMetadataAcrossCallers(t *testing.T) {
	reader := startReaderFixture(t, 100)
	var calls atomic.Uint64
	reader.clockTicks = func() (uint64, error) { return 99 + calls.Add(1), nil }
	const count = 32
	values, errs := make([]int64, count), make([]error, count)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range count {
		wg.Go(func() { <-start; values[i], errs[i] = reader.startTime(42) })
	}
	close(start)
	wg.Wait()
	for i := range count {
		require.NoError(t, errs[i])
		assert.Equal(t, int64(1700000002500), values[i])
	}
	assert.Equal(t, uint64(1), calls.Load())
}

func TestProcessStartReaderRetriesMissingBootMetadata(t *testing.T) {
	reader := startReaderFixture(t, 100)
	require.NoError(t, os.Remove(filepath.Join(reader.procRoot, "stat")))
	_, err := reader.startTime(42)
	require.Error(t, err)
	assert.False(t, processGone(err), "missing kernel metadata does not prove process exit")
	require.NoError(t, os.WriteFile(filepath.Join(reader.procRoot, "stat"), []byte("btime 1700000000\n"), 0600))
	started, err := reader.startTime(42)
	require.NoError(t, err)
	assert.Equal(t, int64(1700000002500), started)
}

func TestProcessStartReaderRetriesClockMetadataErrors(t *testing.T) {
	reader := startReaderFixture(t, 100)
	reads := 0
	reader.clockTicks = func() (uint64, error) {
		reads++
		if reads == 1 {
			return 0, syscall.ESRCH
		}
		return 100, nil
	}
	_, err := reader.startTime(42)
	require.Error(t, err)
	assert.False(t, processGone(err))
	started, err := reader.startTime(42)
	require.NoError(t, err)
	assert.Equal(t, int64(1700000002500), started)
}

func TestProcessStartReaderReportsMissingProcess(t *testing.T) {
	reader := startReaderFixture(t, 100)
	_, err := reader.startTime(43)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.True(t, processGone(err))
}

func TestProcessStartReaderRejectsInvalidMetadata(t *testing.T) {
	for _, tc := range []struct {
		boot string
		hz   uint64
	}{
		{"cpu 1 2 3\n", 100},
		{"btime nope\n", 100},
		{"btime 0\n", 100},
		{"btime -1\n", 100},
		{"btime 18446744073709551615\n", 100},
		{"btime 1700000000 extra\n", 100},
		{"btime 1700000000\n", 0},
	} {
		reader := startReaderFixture(t, tc.hz)
		require.NoError(t, os.WriteFile(filepath.Join(reader.procRoot, "stat"), []byte(tc.boot), 0600))
		_, err := reader.startTime(42)
		require.Error(t, err)
		assert.False(t, processGone(err))
	}
}

func TestProcessStartTickParser(t *testing.T) {
	for _, name := range []string{"sleep", "a process (with) parentheses)", "line\nbreak"} {
		data := strings.Replace(processStatFixture, "(sleep)", "("+name+")", 1)
		ticks, err := parseProcessStartTicks([]byte(data))
		require.NoError(t, err)
		assert.Equal(t, uint64(250), ticks)
	}
	data := strings.Replace(processStatFixture, " 250 ", " 0 ", 1)
	ticks, err := parseProcessStartTicks([]byte(data))
	require.NoError(t, err)
	assert.Zero(t, ticks)
}

func TestProcessStartTickParserRejectsMalformedInput(t *testing.T) {
	for _, data := range []string{
		"", "42 sleep) S 1", "42 (sleep S 1", "42 (sleep) S 1",
		strings.Replace(processStatFixture, "42 (sleep)", "nope (sleep)", 1),
		strings.Replace(processStatFixture, " 250 ", " -1 ", 1),
		strings.Replace(processStatFixture, " 250 ", " 18446744073709551616 ", 1),
	} {
		_, err := parseProcessStartTicks([]byte(data))
		assert.Error(t, err)
	}
}
