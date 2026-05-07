//go:build !windows

package file

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync/atomic"
)

type cmdReadCloser struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	stderr *bytes.Buffer
	closed atomic.Bool
}

func newCmdReadCloser(cmd *exec.Cmd) (*cmdReadCloser, error) {
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		// StdoutPipe-allocated descriptor is not auto-closed on Start failure
		// (Wait never runs), so close it here to avoid an fd leak.
		_ = out.Close()
		return nil, err
	}
	return &cmdReadCloser{cmd: cmd, stdout: out, stderr: &errBuf}, nil
}

func (r *cmdReadCloser) Read(p []byte) (int, error) { return r.stdout.Read(p) }

func (r *cmdReadCloser) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = r.stdout.Close()
	if werr := r.cmd.Wait(); werr != nil {
		msg := strings.TrimSpace(r.stderr.String())
		if msg == "" {
			return werr
		}
		return fmt.Errorf("%w: %s", werr, msg)
	}
	return nil
}
