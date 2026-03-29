package register

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/alpacax/alpamon/pkg/utils"
)

const alpamonBinPath = "/usr/local/bin/alpamon"

func ensureDirectories() error {
	if utils.HasSystemd() {
		if output, err := exec.Command("systemd-tmpfiles", "--create", "alpamon.conf").CombinedOutput(); err != nil {
			return fmt.Errorf("tmpfiles creation failed: %w\n%s", err, string(output))
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
