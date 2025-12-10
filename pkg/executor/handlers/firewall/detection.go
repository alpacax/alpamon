package firewall

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/rs/zerolog/log"
)

// FirewallBackend represents the detected firewall backend type
type FirewallBackend string

const (
	BackendNone     FirewallBackend = "none"
	BackendIptables FirewallBackend = "iptables"
	BackendNftables FirewallBackend = "nftables"
)

// HighLevelFirewall represents high-level firewall management tools
type HighLevelFirewall string

const (
	HighLevelNone      HighLevelFirewall = ""
	HighLevelUFW       HighLevelFirewall = "ufw"
	HighLevelFirewalld HighLevelFirewall = "firewalld"
)

// DetectionResult holds the cached detection results
type DetectionResult struct {
	Backend           FirewallBackend
	HighLevel         HighLevelFirewall
	NftablesAvailable bool
	IptablesAvailable bool
	Disabled          bool
	DetectedAt        time.Time
}

// FirewallDetector detects available firewall backends and high-level tools
type FirewallDetector struct {
	executor common.CommandExecutor
	result   *DetectionResult
	mu       sync.RWMutex
}

// NewFirewallDetector creates a new firewall detector
func NewFirewallDetector(executor common.CommandExecutor) *FirewallDetector {
	return &FirewallDetector{
		executor: executor,
	}
}

// Detect performs full firewall detection
// Returns cached result if already detected, otherwise performs detection
func (d *FirewallDetector) Detect(ctx context.Context) *DetectionResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Return cached result if available
	if d.result != nil {
		return d.result
	}

	result := &DetectionResult{
		DetectedAt: time.Now(),
	}

	// First check for high-level firewall tools
	result.HighLevel = d.detectHighLevelFirewall(ctx)
	if result.HighLevel != HighLevelNone {
		result.Disabled = true
		result.Backend = BackendNone
		d.result = result
		return result
	}

	// Detect backend based on existing rules
	result.Backend = d.detectBackend(ctx)
	result.NftablesAvailable = result.Backend == BackendNftables
	result.IptablesAvailable = result.Backend == BackendIptables
	result.Disabled = result.Backend == BackendNone

	d.result = result
	return result
}

// GetResult returns the cached detection result without re-detecting
func (d *FirewallDetector) GetResult() *DetectionResult {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.result
}

// Reset clears the cached detection result, forcing re-detection on next call
func (d *FirewallDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.result = nil
}

// IsDisabled returns true if firewall management is disabled
func (d *FirewallDetector) IsDisabled() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.result == nil {
		return false
	}
	return d.result.Disabled
}

// GetBackend returns the detected backend type
func (d *FirewallDetector) GetBackend() FirewallBackend {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.result == nil {
		return BackendNone
	}
	return d.result.Backend
}

// detectHighLevelFirewall detects if high-level firewall management tools are active
func (d *FirewallDetector) detectHighLevelFirewall(ctx context.Context) HighLevelFirewall {
	// Check ufw via systemctl (most reliable)
	exitCode, output, _ := d.executor.RunWithTimeout(ctx, 5*time.Second, "systemctl", "is-active", "ufw")
	if exitCode == 0 && strings.TrimSpace(output) == "active" {
		log.Info().Msg("Detected active ufw firewall - alpacon firewall management will be disabled")
		return HighLevelUFW
	}

	// Fallback: Check ufw via direct command
	exitCode, output, _ = d.executor.RunWithTimeout(ctx, 5*time.Second, "ufw", "status")
	if exitCode == 0 && strings.Contains(strings.ToLower(output), "status: active") {
		log.Info().Msg("Detected active ufw firewall - alpacon firewall management will be disabled")
		return HighLevelUFW
	}

	// Check firewalld via systemctl
	exitCode, output, _ = d.executor.RunWithTimeout(ctx, 5*time.Second, "systemctl", "is-active", "firewalld")
	if exitCode == 0 && strings.TrimSpace(output) == "active" {
		log.Info().Msg("Detected active firewalld - alpacon firewall management will be disabled")
		return HighLevelFirewalld
	}

	// Fallback: Check firewalld via firewall-cmd
	exitCode, output, _ = d.executor.RunWithTimeout(ctx, 5*time.Second, "firewall-cmd", "--state")
	if exitCode == 0 && strings.Contains(strings.ToLower(output), "running") {
		log.Info().Msg("Detected active firewalld - alpacon firewall management will be disabled")
		return HighLevelFirewalld
	}

	log.Debug().Msg("No high-level firewall detected - alpacon firewall management enabled")
	return HighLevelNone
}

// detectBackend detects which firewall backend to use based on existing rules
func (d *FirewallDetector) detectBackend(ctx context.Context) FirewallBackend {
	// Try iptables-save to check for existing iptables rules
	exitCode, output, _ := d.executor.RunWithTimeout(ctx, 10*time.Second, "iptables-save")

	if exitCode == 0 {
		// Count actual rules (lines starting with -A or -I)
		ruleCount := 0
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-I ") {
				ruleCount++
			}
		}

		if ruleCount > 0 {
			log.Debug().Msgf("Found %d iptables rules", ruleCount)
			return BackendIptables
		}

		// iptables-save succeeded but no rules - check if nft is available
		exitCode, _, _ := d.executor.RunWithTimeout(ctx, 5*time.Second, "which", "nft")
		if exitCode == 0 {
			log.Debug().Msg("No iptables rules, nft available")
			return BackendNftables
		}

		// Only iptables available, no nft
		log.Debug().Msg("No iptables rules, nft not available, defaulting to iptables")
		return BackendIptables
	}

	// iptables-save failed, try fallback with iptables -S
	exitCode, output, _ = d.executor.RunWithTimeout(ctx, 10*time.Second, "iptables", "-S")
	if exitCode == 0 {
		// Check for rules (iptables -S output starts with -P, -A, -I, etc)
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-I ") {
				log.Debug().Msg("Found iptables rules via iptables -S")
				return BackendIptables
			}
		}
	}

	// No iptables rules found, check if nft is available
	exitCode, _, _ = d.executor.RunWithTimeout(ctx, 5*time.Second, "which", "nft")
	if exitCode == 0 {
		log.Debug().Msg("No iptables rules, using nftables")
		return BackendNftables
	}

	// Neither iptables nor nft available
	log.Warn().Msg("No firewall backend available")
	return BackendNone
}

// CreateBackend creates the appropriate backend based on detection result
func (d *FirewallDetector) CreateBackend(ctx context.Context) FirewallBackendInterface {
	result := d.Detect(ctx)

	if result.Disabled {
		return nil
	}

	switch result.Backend {
	case BackendIptables:
		return NewIptablesBackend(d.executor)
	case BackendNftables:
		return NewNftablesBackend(d.executor)
	default:
		return nil
	}
}
