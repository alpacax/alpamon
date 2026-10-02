package shell

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellHandler_StreamingForwardsCallback(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("echo hi", 0, "hi", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	var captured []string
	args := &common.CommandArgs{
		Command:       "echo hi",
		ChunkCallback: func(_ context.Context, content string) { captured = append(captured, content) },
	}

	_, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)
	require.NoError(t, err, "Execute")

	assert.Equal(t, []string{"hi"}, captured, "expected one chunk 'hi'")
}

// Regression: the same callback must fire for every sub-command across
// operators so the runner-owned seq stays monotonic.
func TestShellHandler_StreamingAcrossOperators(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1", 0, "out1", nil)
	mockExec.SetResult("cmd2", 0, "out2", nil)
	mockExec.SetResult("cmd3", 0, "out3", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	type chunk struct {
		seq     int
		content string
	}
	var seq int
	var captured []chunk
	callback := func(_ context.Context, content string) {
		captured = append(captured, chunk{seq: seq, content: content})
		seq++
	}

	args := &common.CommandArgs{
		Command:       "cmd1 && cmd2 ; cmd3",
		ChunkCallback: callback,
	}

	_, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)
	require.NoError(t, err, "Execute")

	require.Len(t, captured, 3, "expected 3 chunks across operators (%v)", captured)

	expected := []chunk{
		{seq: 0, content: "out1"},
		{seq: 1, content: "out2"},
		{seq: 2, content: "out3"},
	}
	for i, c := range captured {
		assert.Equal(t, expected[i], c, "chunk[%d]", i)
	}
}

// Regression: under streaming the fin result must still carry the accumulated
// per-segment output for audit, not be dropped to "".
func TestShellHandler_StreamingOperatorsReturnAuditResult(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1", 0, "out1", nil)
	mockExec.SetResult("cmd2", 0, "out2", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command:       "cmd1 && cmd2",
		ChunkCallback: func(_ context.Context, content string) {},
	}

	_, result, err := handler.Execute(ctx, common.ShellCmd.String(), args)
	require.NoError(t, err, "Execute")
	assert.Equal(t, "out1out2", result, "fin result should accumulate streamed segment output")
}

func TestShellHandler_NilChunkCallback(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("ls", 0, "file.txt", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command:       "ls",
		ChunkCallback: nil,
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)
	require.NoError(t, err, "Execute")
	assert.Equal(t, 0, exitCode, "exit code")
	assert.NotEmpty(t, output, "expected non-empty output")
}
