package register

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/alpacax/alpamon/pkg/utils"
)

const (
	alpamonBinPathFallback = "/usr/local/bin/alpamon"
	plistName              = "com.alpacax.alpamon.plist"
	launchdDir             = "/Library/LaunchDaemons"
)

// getAlpamonBinPath returns the path of the currently running alpamon binary.
// This handles Homebrew installations where the binary may be at /opt/homebrew/bin/alpamon
// (Apple Silicon) instead of the default /usr/local/bin/alpamon (Intel).
// Note: symlinks are intentionally NOT resolved so that the plist uses the stable
// symlink path (e.g. /opt/homebrew/bin/alpamon) rather than a version-pinned
// Cellar path that would break after brew upgrade.
func getAlpamonBinPath() string {
	if exe, err := os.Executable(); err == nil {
		if abs, err := filepath.Abs(exe); err == nil {
			return abs
		}
		return exe
	}
	return alpamonBinPathFallback
}

func ensureDirectories() error {
	return utils.EnsureDirectories()
}

func startService() error {
	plistDst := filepath.Join(launchdDir, plistName)

	// Generate plist if not already installed
	if _, err := os.Stat(plistDst); os.IsNotExist(err) {
		if err := writeLaunchdPlist(plistDst); err != nil {
			return fmt.Errorf("failed to install launchd plist: %w", err)
		}
	}

	if output, err := exec.Command("launchctl", "load", plistDst).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load failed: %w\n%s", err, string(output))
	}

	fmt.Println("Alpamon service loaded via launchd.")
	return nil
}

func writeLaunchdPlist(path string) error {
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.alpacax.alpamon</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>/var/log/alpamon.err</string>
	<key>StandardOutPath</key>
	<string>/var/log/alpamon.out</string>
	<key>WorkingDirectory</key>
	<string>/</string>
</dict>
</plist>
`, getAlpamonBinPath())

	return os.WriteFile(path, []byte(plist), 0644)
}

func printManualStartHint() {
	fmt.Println("Please start the service manually:")
	fmt.Printf("  sudo launchctl load %s/%s\n", launchdDir, plistName)
}
