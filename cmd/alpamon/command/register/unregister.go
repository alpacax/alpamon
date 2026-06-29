package register

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/migrate"
	"github.com/spf13/cobra"
)

var (
	unregisterSSLVerify  bool
	unregisterCaCert     string
	unregisterYes        bool
	unregisterKeepConfig bool
)

// UnregisterCmd reverses register: it drops the server record on the Alpacon
// console, stops/removes the OS service, and deletes the local config so the
// host can be registered again. It is the supported recovery path for a server
// stuck after a failed register (where re-running register hits the
// "config file already exists" wall).
var UnregisterCmd = &cobra.Command{
	Use:   "unregister",
	Short: "Unregister this server and remove local registration state",
	Long: `Unregister this server so it can be registered again.

Reads the existing config, best-effort deletes the server record on the Alpacon
console, stops and removes the OS service, and deletes the local config file.
Data/log directories and the agent binary are left in place.

Run this on the server itself (locally or via an out-of-band console such as
RDP / cloud serial console / SSM) — not over Websh, since stopping the service
would terminate the Websh session before the command finishes.

Run before re-registering a server whose previous 'register' failed, or use
'alpamon register --force' to do both in one step.`,
	RunE: runUnregister,
}

func init() {
	UnregisterCmd.Flags().BoolVar(&unregisterSSLVerify, "ssl-verify", true, "SSL certificate verification")
	UnregisterCmd.Flags().StringVar(&unregisterCaCert, "ca-cert", "", "CA certificate path")
	UnregisterCmd.Flags().BoolVar(&unregisterYes, "yes", false, "Skip the confirmation prompt (required for non-interactive use)")
	UnregisterCmd.Flags().BoolVar(&unregisterKeepConfig, "keep-config", false, "Remove the remote record and service but keep the local config (debug)")
}

func runUnregister(_ *cobra.Command, _ []string) error {
	// On Windows, run from the installed location so SCM operations match the
	// service register created. No-op on Linux/macOS.
	if relaunched, err := ensureInstalled(); err != nil {
		return err
	} else if relaunched {
		return nil
	}

	srv, err := config.ReadServer(configPath)
	if err != nil {
		// No usable config: nothing local to clean. The remote record (if any)
		// can only be removed from the console.
		fmt.Printf("No registration found at %s (%v).\n", configPath, err)
		fmt.Println("If a stale server still shows in the Alpacon console, remove it there.")
		return nil
	}

	if !unregisterYes && !confirm(fmt.Sprintf("Unregister server %s from %s and remove local state?", srv.ID, srv.URL)) {
		return fmt.Errorf("aborted")
	}

	// Remote delete first (smallest-orphan ordering); best-effort, never fatal.
	fmt.Printf("Unregistering %s from %s ...\n", srv.ID, srv.URL)
	migrate.BestEffortUnregister(srv.URL, srv.ID, srv.Key, unregisterSSLVerify, unregisterCaCert)

	if err := removeServiceFn(); err != nil {
		fmt.Printf("Warning: failed to remove service: %v\n", err)
	}

	if !unregisterKeepConfig {
		if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove config %s: %w", configPath, err)
		}
	}

	// The remote DELETE is best-effort (logged, not surfaced), so be honest that
	// the local side is cleared but the console record should be verified.
	fmt.Println("Local registration state removed. The remote record was deleted on a")
	fmt.Println("best-effort basis — verify in the Alpacon console if it still appears.")
	fmt.Println("You can run 'alpamon register' again.")
	return nil
}

// confirm prompts on stdin and returns true only on an explicit "y"/"yes". Any
// other answer, or a read error (e.g. piped/empty stdin in a non-interactive
// context without --yes), returns false so the destructive action safely aborts
// rather than proceeding.
func confirm(prompt string) bool {
	// Prompt on stderr so stdout stays clean when the command output is piped.
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
