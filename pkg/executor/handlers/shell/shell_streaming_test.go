package shell

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
)

// TestShellHandler_StreamingForwardsCallback verifies that a ChunkCallback
// set on CommandArgs is forwarded down to the executor for a single
// sub-command path (no shell operators).
func TestShellHandler_StreamingForwardsCallback(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("echo hi", 0, "hi", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	var captured []string
	args := &common.CommandArgs{
		Command:       "echo hi",
		ChunkCallback: func(content string) { captured = append(captured, content) },
	}

	if _, _, err := handler.Execute(ctx, common.ShellCmd.String(), args); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(captured) != 1 || captured[0] != "hi" {
		t.Errorf("expected one chunk 'hi', got %v", captured)
	}
}

// TestShellHandler_StreamingAcrossOperators is the regression test for the
// seq-collision bug: when executeWithOperators runs multiple sub-commands
// for one logical command, the same ChunkCallback must be invoked for each
// sub-command. Because seq is owned by the caller (CommandRunner), this
// test asserts that the runner-side counter would observe each chunk
// exactly once in order — regardless of how many sub-commands run.
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
	callback := func(content string) {
		captured = append(captured, chunk{seq: seq, content: content})
		seq++
	}

	args := &common.CommandArgs{
		Command:       "cmd1 && cmd2 ; cmd3",
		ChunkCallback: callback,
	}

	if _, _, err := handler.Execute(ctx, common.ShellCmd.String(), args); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(captured) != 3 {
		t.Fatalf("expected 3 chunks across operators, got %d (%v)", len(captured), captured)
	}

	expected := []chunk{
		{seq: 0, content: "out1"},
		{seq: 1, content: "out2"},
		{seq: 2, content: "out3"},
	}
	for i, c := range captured {
		if c != expected[i] {
			t.Errorf("chunk[%d]: got %+v, want %+v", i, c, expected[i])
		}
	}
}

// TestShellHandler_NilChunkCallback ensures the streaming path stays optional:
// when ChunkCallback is nil, executeCommand must fall back to the non-streaming
// ExecWithHook / Exec path without panic.
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
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}
	if output == "" {
		t.Error("expected non-empty output")
	}
}
