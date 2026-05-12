package cloud

import (
	"context"
	"os"
	"runtime"
	"strings"
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
//   - all probes fail and ctx is healthy: returns
//     (nil, nil, ErrNoCloudProvider). Callers must treat this as a normal
//     on-prem / dev path, not a failure.
//   - ctx is canceled or times out at any point: returns (nil, nil, ctx.Err()).
//     This is distinct from ErrNoCloudProvider so callers can tell "no provider"
//     apart from "detection aborted by timeout/cancel" — including the edge
//     case where ctx expires during the last provider's Probe.
//   - probe succeeds and Fetch succeeds: returns (provider, fullMeta, nil).
//   - probe succeeds but Fetch errors mid-read: returns
//     (provider, partialMeta, fetchErr). Caller gets to decide how to surface
//     the partial result. We never fall through to another provider once a
//     probe is positive — IMDS responses are provider-specific, so partial
//     data is strictly better than wrong-provider data.
//
// Detect is a pure library function: it does not log. Callers that need to
// surface failures (e.g. the register CLI) should inspect the returned error
// and format it in their own output style.
func Detect(ctx context.Context, providers []Provider) (Provider, *Metadata, error) {
	if len(providers) == 0 {
		return nil, nil, ErrNoCloudProvider
	}

	ordered := reorderByDMI(providers, readDMIHint())

	for _, p := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if !p.Probe(ctx) {
			continue
		}

		meta, err := p.Fetch(ctx)
		if meta == nil {
			meta = &Metadata{Provider: p.Name()}
		}
		return p, meta, err
	}
	// ctx may have expired during the last Probe; surface that rather than
	// the generic ErrNoCloudProvider so callers can distinguish timeout from
	// "host is not on any of the known clouds".
	if err := ctx.Err(); err != nil {
		return nil, nil, err
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
