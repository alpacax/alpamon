package cloud

import (
	"context"
	"os"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
)

// dmiPaths lists the sysfs DMI files queried for a cloud-provider hint on
// Linux. Order matters only as a tie-breaker — the first file whose contents
// classify cleanly via classifyDMI wins.
var dmiPaths = []string{
	"/sys/class/dmi/id/sys_vendor",
	"/sys/class/dmi/id/chassis_asset_tag",
	"/sys/class/dmi/id/board_vendor",
	"/sys/class/dmi/id/bios_vendor",
}

// Detect probes the supplied providers in order and returns the first one that
// responds on its IMDS endpoint. On Linux, a DMI hint is consulted first so we
// don't burn 800 ms probing the wrong provider on the common case (single-cloud
// hosts have a strong identifying string in sys_vendor / chassis_asset_tag).
//
// Return contract:
//   - all probes fail: returns (nil, nil, ErrNoCloudProvider). Callers must
//     treat this as a normal on-prem / dev path, not a failure.
//   - probe succeeds and Fetch succeeds: returns (provider, fullMeta, nil).
//   - probe succeeds but Fetch errors mid-read: returns
//     (provider, partialMeta, fetchErr). Caller gets to decide how to surface
//     the partial result. We never fall through to another provider once a
//     probe is positive — IMDS responses are provider-specific, so partial
//     data is strictly better than wrong-provider data.
//
// Returning the Fetch error (rather than swallowing it) lets register surface
// partial-detection diagnostics to the operator instead of silently shipping
// an incomplete tag set.
func Detect(ctx context.Context, providers []Provider) (Provider, *Metadata, error) {
	if len(providers) == 0 {
		return nil, nil, ErrNoCloudProvider
	}

	ordered := reorderByDMI(providers, readDMIHint())

	for _, p := range ordered {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if !p.Probe(ctx) {
			continue
		}

		meta, err := p.Fetch(ctx)
		if err != nil {
			log.Warn().Err(err).Str("provider", p.Name()).Msg("cloud metadata fetch returned partial data")
		}
		if meta == nil {
			meta = &Metadata{Provider: p.Name()}
		}
		return p, meta, err
	}
	return nil, nil, ErrNoCloudProvider
}

// reorderByDMI moves the provider matching the DMI hint to the front. If the
// hint is empty or doesn't match any provider, the original order is preserved.
// This is a pure optimization — Detect's correctness does not depend on it.
func reorderByDMI(providers []Provider, hint string) []Provider {
	if hint == "" {
		return providers
	}
	idx := -1
	for i, p := range providers {
		if p.Name() == hint {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return providers
	}
	out := make([]Provider, 0, len(providers))
	out = append(out, providers[idx])
	out = append(out, providers[:idx]...)
	out = append(out, providers[idx+1:]...)
	return out
}

// readDMIHint returns a provider name ("aws"/"gcp"/"azure") if a DMI field
// gives a strong signal, otherwise "". Linux-only — macOS and Windows skip
// this and rely on Probe ordering.
func readDMIHint() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	for _, path := range dmiPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if name := classifyDMI(string(data)); name != "" {
			return name
		}
	}
	return ""
}

// classifyDMI examines a DMI field value and reports the matching provider.
// Match patterns are conservative — we'd rather return "" (fall back to
// sequential probing) than incorrectly skip a provider.
func classifyDMI(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(v, "amazon"), strings.Contains(v, "aws"):
		return ProviderAWS
	case strings.Contains(v, "google"):
		return ProviderGCP
	case strings.Contains(v, "microsoft corporation"):
		return ProviderAzure
	}
	return ""
}

// DefaultProviders returns the production provider list in detect priority.
func DefaultProviders() []Provider {
	return []Provider{NewAWS(), NewGCP(), NewAzure()}
}
