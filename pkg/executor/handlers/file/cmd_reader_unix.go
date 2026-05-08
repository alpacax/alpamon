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

const stderrCapSize = 8 << 10 // 8 KiB — enough for any error message

// stderrCap collects up to cap bytes of stderr and silently discards the rest.
type stderrCap struct {
	buf bytes.Buffer
	cap int
}

type cmdReadCloser struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	stderr *stderrCap
	closed atomic.Bool
}

func (w *stderrCap) Write(p []byte) (int, error) {
	if rem := w.cap - w.buf.Len(); rem > 0 {
		if len(p) > rem {
			p = p[:rem]
		}
		w.buf.Write(p)
	}
	return len(p), nil
}

func newCmdReadCloser(cmd *exec.Cmd) (*cmdReadCloser, error) {
	errW := &stderrCap{cap: stderrCapSize}
	cmd.Stderr = errW
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
	return &cmdReadCloser{cmd: cmd, stdout: out, stderr: errW}, nil
}

func (r *cmdReadCloser) Read(p []byte) (int, error) { return r.stdout.Read(p) }

func (r *cmdReadCloser) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = r.stdout.Close()
	if werr := r.cmd.Wait(); werr != nil {
		msg := strings.TrimSpace(r.stderr.buf.String())
		if msg == "" {
			return werr
		}
		return fmt.Errorf("%w: %s", werr, msg)
	}
	return nil
}
