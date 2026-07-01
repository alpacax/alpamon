package shell

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
)

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
		ChunkCallback: func(content string) {},
	}

	_, result, err := handler.Execute(ctx, common.ShellCmd.String(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result != "out1out2" {
		t.Errorf("fin result should accumulate streamed segment output, got %q", result)
	}
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
