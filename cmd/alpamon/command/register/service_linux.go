package register

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"syscall"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

const alpamonBinPath = "/usr/bin/alpamon"

func ensureDirectories() error {
	if utils.HasSystemd() {
		if output, err := exec.Command("systemd-tmpfiles", "--create", "alpamon.conf").CombinedOutput(); err != nil {
			return fmt.Errorf("tmpfiles creation failed: %w\n%s", err, string(output))
		}
		// systemd-tmpfiles can exit 0 without creating the directory (e.g. on
		// systemd <235 that ignores parts of the drop-in, or when the drop-in
		// is unresolved). Without this fallback the service crash-loops on
		// 200/CHDIR because WorkingDirectory does not exist. Only "does not
		// exist" triggers the fallback; permission/IO errors and a non-dir
		// path are surfaced so packaging or filesystem faults are not masked.
		dataDir := utils.DataDir()
		info, err := os.Stat(dataDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return utils.EnsureDirectories()
			}
			return fmt.Errorf("stat %s: %w", dataDir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", dataDir)
		}
		return nil
	}
	return utils.EnsureDirectories()
}

func startService() error {
	if utils.HasSystemd() {
		if output, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			return fmt.Errorf("daemon-reload failed: %w\n%s", err, string(output))
		}

		if output, err := exec.Command("systemctl", "start", "alpamon.service").CombinedOutput(); err != nil {
			return fmt.Errorf("start failed: %w\n%s", err, string(output))
		}

		if output, err := exec.Command("systemctl", "enable", "alpamon.service").CombinedOutput(); err != nil {
			return fmt.Errorf("enable failed: %w\n%s", err, string(output))
		}

		fmt.Println("Alpamon service started and enabled.")
		return nil
	}

	// Start alpamon as a background process (containers without systemd)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", logPath, err)
	}

	cmd := exec.Command(alpamonBinPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("failed to start alpamon process: %w", err)
	}
	_ = logFile.Close()

	pid := cmd.Process.Pid
	_ = cmd.Process.Release()

	fmt.Printf("Alpamon started (PID: %d).\n", pid)
	fmt.Printf("Logs: %s\n", logPath)
	return nil
}

func printManualStartHint() {
	if utils.HasSystemd() {
		fmt.Println("Please start the service manually:")
		fmt.Println("  sudo systemctl start alpamon")
		fmt.Println("  sudo systemctl enable alpamon")
	} else {
		fmt.Println("Please start alpamon manually:")
		fmt.Printf("  %s\n", alpamonBinPath)
	}
}

// stopService stops the alpamon systemd unit without disabling it. Used by
// register --force to bounce the unit so the fresh start reloads the new config.
// Best-effort/idempotent: a `systemctl stop` of an already-stopped or
// non-existent unit is ignored. No-op on hosts without systemd.
func stopService() error {
	if utils.HasSystemd() {
		_, _ = exec.Command("systemctl", "stop", "alpamon.service").CombinedOutput()
	}
	return nil
}

// removeService stops and disables the alpamon systemd unit (full teardown for
// unregister). Best-effort/idempotent: errors from `systemctl stop`/`disable` on
// an already-stopped or non-existent unit are intentionally ignored so
// unregister never fails on an already-clean box. On hosts without systemd there
// is no durable service to remove (the agent runs as a detached background
// process that exits on host teardown).
func removeService() error {
	if utils.HasSystemd() {
		_, _ = exec.Command("systemctl", "stop", "alpamon.service").CombinedOutput()
		_, _ = exec.Command("systemctl", "disable", "alpamon.service").CombinedOutput()
	}
	return nil
}
