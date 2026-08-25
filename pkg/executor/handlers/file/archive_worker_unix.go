//go:build !windows

package file

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

// archiveWorkerCommand is the alpamon subcommand that builds the archive.
// See cmd/alpamon/command/archive.
const archiveWorkerCommand = "archive"

// createArchiveAs builds the archive at destPath. With demotion active the
// work happens in a child process carrying the requesting user's credentials,
// so the directory walk and every file open are subject to that user's
// filesystem permissions. Without demotion, which is every non-root agent, it
// builds in-process, because there is no identity to drop to.
func createArchiveAs(ctx context.Context, destPath string, paths []string, recursive bool, sysProcAttr *syscall.SysProcAttr) (utils.SkippedReport, error) {
	if sysProcAttr == nil {
		skipped, err := utils.CreateZip(destPath, paths, recursive)
		return utils.SkippedReport{Entries: skipped, Total: len(skipped)}, err
	}

	executable, err := os.Executable()
	if err != nil {
		return utils.SkippedReport{}, fmt.Errorf("failed to locate the alpamon binary: %w", err)
	}

	request, err := json.Marshal(utils.ArchiveRequest{Paths: paths, Recursive: recursive})
	if err != nil {
		return utils.SkippedReport{}, fmt.Errorf("failed to build the archive request: %w", err)
	}

	// The parent opens the destination and hands over the descriptor, so the
	// worker never resolves destPath and a path swapped underneath it cannot
	// redirect the archive. O_EXCL because os.TempDir() is world-writable.
	archive, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return utils.SkippedReport{}, err
	}

	cmd := exec.CommandContext(ctx, executable, archiveWorkerCommand)
	cmd.SysProcAttr = sysProcAttr
	cmd.Stdin = bytes.NewReader(request)
	cmd.Stdout = archive
	status := &stderrCap{cap: stderrCapSize}
	cmd.Stderr = status
	// The worker reads nothing from the environment, and it runs as the
	// requesting user, who could otherwise read the agent's environment out
	// of the worker's own /proc entry.
	cmd.Env = []string{}

	runErr := cmd.Run()
	if cerr := archive.Close(); runErr == nil && cerr != nil {
		return utils.SkippedReport{}, cerr
	}

	return archiveWorkerResult(status.buf.String(), runErr)
}

// archiveWorkerResult turns the worker's status stream into the skipped list.
// runErr is the process outcome, which stays authoritative when the status
// cannot be read: a worker killed by the handler timeout never reports.
func archiveWorkerResult(status string, runErr error) (utils.SkippedReport, error) {
	var response utils.ArchiveResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(status)), &response); err != nil {
		if runErr != nil {
			if msg := strings.TrimSpace(status); msg != "" {
				return utils.SkippedReport{}, fmt.Errorf("%w: %s", runErr, msg)
			}
			return utils.SkippedReport{}, runErr
		}
		return utils.SkippedReport{}, fmt.Errorf("failed to read the archive worker status: %w", err)
	}

	report := utils.SkippedReport{Total: response.SkippedTotal}
	for _, entry := range response.Skipped {
		report.Entries = append(report.Entries, utils.SkippedEntry{
			Path:   entry.Path,
			Reason: errors.New(entry.Reason),
		})
	}

	// The total can never be smaller than the sample it came with. A response
	// that carried entries but no total would otherwise make the summary
	// understate what the download left out.
	if report.Total < len(report.Entries) {
		report.Total = len(report.Entries)
	}

	if response.Error != "" {
		return report, errors.New(response.Error)
	}
	if runErr != nil {
		return report, runErr
	}
	return report, nil
}
