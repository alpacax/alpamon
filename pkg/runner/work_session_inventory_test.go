package runner

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listingControl is a process controller that lists a fixed inventory.
type listingControl struct {
	noProcessControl
	processes []WorkSessionProcess
}

func (c listingControl) Inventory(OwnedWork) ([]WorkSessionProcess, error) {
	return c.processes, nil
}

// countingInventory counts posted inventories.
type countingInventory struct {
	mu      sync.Mutex
	reports []WorkSessionProcessInventory
}

func (c *countingInventory) post(inventory WorkSessionProcessInventory) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports = append(c.reports, inventory)
}

func (c *countingInventory) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reports)
}

func stopProcessesFrame(t *testing.T, revision uint64) []byte {
	t.Helper()
	frame, err := json.Marshal(map[string]any{"query": "control", "data": map[string]any{
		"type": "work_session_stop_processes", "protocol_version": 1, "client_id": "server-1",
		"work_session_id": wsID, "action_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "revision": fmt.Sprint(revision),
	}})
	require.NoError(t, err)
	return frame
}

func TestInventoryIsReportedWhilePausedAndOnceAfterResume(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeControlServer{}
		inventories := &countingInventory{}
		r := newTestRegistry(server)
		r.processes = listingControl{processes: []WorkSessionProcess{{Kind: ownedKindCommand, CommandID: "cmd-1", PID: 42, PGID: 42, State: processRunning}}}
		r.postInventory = inventories.post
		cc := &ControlClient{workSessions: r}

		cc.HandleMessage(pauseFrame(t, 1))
		assert.Equal(t, 1, inventories.count(), "reported after the pause")

		time.Sleep(workSessionInventoryInterval)
		synctest.Wait()
		assert.Equal(t, 2, inventories.count(), "reported every 30 seconds while paused")

		cc.HandleMessage(stopProcessesFrame(t, 1))
		assert.Equal(t, 3, inventories.count(), "reported after a Stop")

		cc.HandleMessage(resumeFrame(t, 2))
		assert.Equal(t, 4, inventories.count(), "reported once after Resume")
		last := inventories.reports[3]
		assert.Equal(t, wsID, last.WorkSessionID)
		assert.Equal(t, uint64(2), uint64(last.Revision))
		assert.False(t, last.Truncated)
		assert.Equal(t, []WorkSessionProcess{{Kind: ownedKindCommand, CommandID: "cmd-1", PID: 42, PGID: 42, State: processRunning}}, last.Processes)

		time.Sleep(3 * workSessionInventoryInterval)
		synctest.Wait()
		assert.Equal(t, 4, inventories.count(), "reports stop until the next pause")
	})
}

func TestEndStopsThePeriodicInventory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &fakeControlServer{}
		inventories := &countingInventory{}
		r := newTestRegistry(server)
		r.processes = listingControl{}
		r.postInventory = inventories.post
		cc := &ControlClient{workSessions: r}

		cc.HandleMessage(pauseFrame(t, 1))
		cc.HandleMessage(controlFrame(t, "work_session_end", 2, "ended", "human_end"))
		reported := inventories.count()

		time.Sleep(3 * workSessionInventoryInterval)
		synctest.Wait()
		assert.Equal(t, reported, inventories.count())
	})
}

func TestInventoryCarriesAtMostOneHundredEntries(t *testing.T) {
	server := &fakeControlServer{}
	inventories := &countingInventory{}
	r := newTestRegistry(server)
	processes := make([]WorkSessionProcess, 150)
	for i := range processes {
		processes[i] = WorkSessionProcess{Kind: ownedKindCommand, PID: 1000 + i}
	}
	r.processes = listingControl{processes: processes}
	r.postInventory = inventories.post

	(&ControlClient{workSessions: r}).HandleMessage(pauseFrame(t, 1))
	require.Equal(t, 1, inventories.count())
	report := inventories.reports[0]
	assert.True(t, report.Truncated)
	assert.Len(t, report.Processes, 100)
	(&ControlClient{workSessions: r}).HandleMessage(controlFrame(t, "work_session_end", 2, "ended", "human_end"))
}

func TestInventoryWireShape(t *testing.T) {
	body, err := json.Marshal(WorkSessionProcessInventory{
		WorkSessionID: wsID, Revision: 3, ObservedAt: "2026-11-18T09:00:00Z", Truncated: true,
		Processes: []WorkSessionProcess{{Kind: ownedKindTerminal, CommandID: "cmd-1", PID: 7, PGID: 6, StartedAt: "2026-11-18T08:59:00Z", State: processStopped, Args: []string{"vim"}}},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"work_session_id": "11111111-1111-4111-8111-111111111111", "revision": "3",
		"observed_at": "2026-11-18T09:00:00Z", "truncated": true,
		"processes": [{"kind": "terminal", "command_id": "cmd-1", "pid": 7, "pgid": 6,
			"started_at": "2026-11-18T08:59:00Z", "state": "stopped", "args": ["vim"]}]
	}`, string(body))
}

func TestCutArgsKeepsAtMostTheLimitInBytes(t *testing.T) {
	assert.Equal(t, []string{"ls", "-l"}, cutArgs([]string{"ls", "-l"}, 1024))
	assert.Equal(t, []string{"echo", "abc"}, cutArgs([]string{"echo", "abcdef", "next"}, 7))
	assert.Equal(t, []string{"ab"}, cutArgs([]string{"ab", "x"}, 2))
	assert.Equal(t, []string{"a"}, cutArgs([]string{"a가"}, 3), "a cut never splits a character")
	long := strings.Repeat("x", 2000)
	cut := cutArgs([]string{"sh", "-c", long}, 1024)
	assert.Equal(t, 1024, len(strings.Join(cut, "")))
}

func TestHostWithoutGroupStopReportsUnsupportedAndCancelsOnEnd(t *testing.T) {
	var cancelled []string
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	r.processes = cancelProcessControl{cancel: func(id string) { cancelled = append(cancelled, id) }}
	server.set(workSessionActive, 0)
	release, err := r.admit(t.Context(), attribution(0), "cmd-1")
	require.NoError(t, err)
	defer release()
	r.registerTerminal(wsID, "websh-1", "cmd-open")
	cc := &ControlClient{workSessions: r}

	cc.HandleMessage(pauseFrame(t, 1))
	cc.HandleMessage(stopProcessesFrame(t, 1))
	assert.Equal(t, controlResultUnsupported, server.lastResult(t).Result)

	cc.HandleMessage(controlFrame(t, "work_session_end", 2, "ended", "human_end"))
	ended := server.lastResult(t)
	assert.Equal(t, controlResultUnsupported, ended.Result, "a cancelled job object is not a confirmed tree end")
	assert.Equal(t, []string{"cmd-1", "cmd-open"}, cancelled)
}

func TestCommandProcessSessionIsOwnedThroughItsContext(t *testing.T) {
	server := &fakeControlServer{}
	r := newTestRegistry(server)
	ctx := withWorkSession(t.Context(), &workSessionBinding{registry: r, attribution: attribution(0)})

	TrackWorkSessionProcess(ctx, "cmd-1", 4242)
	TrackWorkSessionProcess(t.Context(), "cmd-2", 4343)

	r.mu.Lock()
	sessions := r.sessions[wsID].owned().Sessions
	r.mu.Unlock()
	require.Len(t, sessions, 1)
	assert.Equal(t, ownedKindCommand, sessions[0].Kind)
	assert.Equal(t, "cmd-1", sessions[0].CommandID)
	assert.Equal(t, 4242, sessions[0].SID)
}
