package cloud

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GCE metadata server endpoints. We target the link-local IP directly rather
// than the canonical hostname metadata.google.internal. Reasoning:
//
//   - DNS dependency: a hostname lookup can resolve to a non-link-local
//     address on hosts with split-horizon DNS, custom search domains, or a
//     compromised resolver, allowing off-host HTTP requests that may spoof
//     GCE responses and produce wrong cloud:* tags. The IP cannot be
//     redirected by DNS.
//   - Defense in depth: AWS and Azure already use link-local IPs. Using the
//     same approach for GCP gives us a uniform untrustworthy-network policy.
//   - Provider discrimination: cross-fire on the shared 169.254.169.254 with
//     AWS and Azure is prevented by the Metadata-Flavor: Google REQUEST header
//     (which AWS/Azure won't echo) and the response-header validation in
//     get() that requires Metadata-Flavor: Google in the response.
//
// GCE listens on both 169.254.169.254 (IPv4) and fd00:ec2::254 (IPv6). We use
// IPv4 to match AWS/Azure; IPv6-only GCE hosts are rare and can be supported
// by future override via NewGCPWithBase.
const (
	gcpDefaultBase = "http://169.254.169.254"

	gcpInstanceIDPath  = "/computeMetadata/v1/instance/id"
	gcpZonePath        = "/computeMetadata/v1/instance/zone"
	gcpMachineTypePath = "/computeMetadata/v1/instance/machine-type"
	gcpNetworkPath     = "/computeMetadata/v1/instance/network-interfaces/0/network"
	gcpProjectIDPath   = "/computeMetadata/v1/project/project-id"

	// gcpFlavorHeader prevents accidental cross-origin reads — GCE rejects
	// requests without this exact header.
	gcpFlavorHeader = "Metadata-Flavor"
	gcpFlavorValue  = "Google"

	gcpResponseLimit = 4 * 1024
)

const (
	gcpProbeTimeout = 800 * time.Millisecond
	gcpFetchTimeout = 2 * time.Second
)

// GCPProvider implements Provider against the GCE metadata server.
type GCPProvider struct {
	base   string
	client *http.Client
}

// NewGCP returns a GCP provider pointed at the link-local IP 169.254.169.254
// (see gcpDefaultBase for why we use the IP directly rather than the canonical
// metadata.google.internal hostname).
func NewGCP() *GCPProvider { return NewGCPWithBase(gcpDefaultBase) }

// NewGCPWithBase constructs a GCP provider against an arbitrary base URL. Used
// by tests.
func NewGCPWithBase(base string) *GCPProvider {
	return &GCPProvider{
		base:   strings.TrimRight(base, "/"),
		client: newIMDSClient(gcpFetchTimeout + 500*time.Millisecond),
	}
}

// Name implements Provider.
func (p *GCPProvider) Name() string { return ProviderGCP }

// Probe reads the instance-id endpoint. A successful 200 with the
// Metadata-Flavor: Google response header (validated inside get) is the
// strongest signal that this is GCE — bare 200s without the header are
// rejected as not-GCP (e.g. a captive portal returning a generic 200).
func (p *GCPProvider) Probe(ctx context.Context) bool {
	probeCtx, cancel := context.WithTimeout(ctx, gcpProbeTimeout)
	defer cancel()

	_, err := p.get(probeCtx, gcpInstanceIDPath)
	return err == nil
}

// Fetch retrieves the full metadata snapshot. Each sub-fetch is best-effort —
// failures leave the corresponding Metadata field empty rather than aborting
// the whole call, since GCE returns 404 (not 500) for genuinely-missing fields.
func (p *GCPProvider) Fetch(ctx context.Context) (*Metadata, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, gcpFetchTimeout)
	defer cancel()

	meta := &Metadata{Provider: ProviderGCP}

	id, err := p.get(fetchCtx, gcpInstanceIDPath)
	if err != nil {
		return meta, fmt.Errorf("gcp instance-id: %w", err)
	}
	meta.InstanceID = strings.TrimSpace(string(id))
	// instance_id is the deterministic-match key. A misbehaving IMDS that
	// returns 200 with an empty body would otherwise produce a useless tag
	// set with no cloud:instance_id — fail explicitly instead.
	if meta.InstanceID == "" {
		return meta, fmt.Errorf("gcp imds returned empty instance id")
	}

	if zone, err := p.get(fetchCtx, gcpZonePath); err == nil {
		az := basename(string(zone))
		meta.AvailabilityZone = az
		meta.Region = zoneToRegion(az)
	}
	if mt, err := p.get(fetchCtx, gcpMachineTypePath); err == nil {
		meta.InstanceType = basename(string(mt))
	}
	if net, err := p.get(fetchCtx, gcpNetworkPath); err == nil {
		meta.NetworkID = basename(string(net))
	}
	if proj, err := p.get(fetchCtx, gcpProjectIDPath); err == nil {
		meta.AccountID = strings.TrimSpace(string(proj))
	}

	return meta, nil
}

func (p *GCPProvider) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(gcpFlavorHeader, gcpFlavorValue)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp %s http %d", path, resp.StatusCode)
	}
	// GCE metadata server always echoes Metadata-Flavor: Google in responses.
	// Absence rules out a real GCE responder (a captive portal or spoofed
	// 169.254.169.254 listener could return 200 to anything), so we treat the
	// header as authoritative provider discrimination, not just a hint.
	if got := resp.Header.Get(gcpFlavorHeader); got != gcpFlavorValue {
		return nil, fmt.Errorf("gcp %s missing Metadata-Flavor response header (got %q)", path, got)
	}
	return readLimitedN(resp.Body, gcpResponseLimit)
}

// basename returns the final path segment of a slash-separated string.
// GCE metadata returns full resource paths like "projects/123/zones/us-central1-a";
// we only care about the leaf.
func basename(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		return s[idx+1:]
	}
	return s
}

// zoneToRegion strips the trailing zone suffix from a GCE zone name.
// "us-central1-a" → "us-central1". GCE zones are always region-letter where
// letter is exactly one character (a/b/c/...). If the final segment after the
// last "-" is anything other than one character, the input is treated as
// already a region (or otherwise malformed) and returned unchanged. This
// guards against inputs like "us-central1" being incorrectly chopped to "us".
func zoneToRegion(zone string) string {
	idx := strings.LastIndex(zone, "-")
	if idx <= 0 {
		return zone
	}
	if len(zone)-idx-1 != 1 {
		// suffix is not a single zone letter — input is already a region or
		// is otherwise non-zone-shaped (defensive).
		return zone
	}
	return zone[:idx]
}
