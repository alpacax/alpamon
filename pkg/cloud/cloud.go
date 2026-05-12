// Package cloud detects the host's cloud provider (AWS, GCP, Azure) via the
// provider-specific instance metadata service (IMDS) and exposes the result
// as a tag map prefixed cloud:* that alpacon-server matches against
// CloudInstance records during reconcile.
package cloud

import (
	"context"
	"errors"
)

// ErrNoCloudProvider is returned by Detect when no provider responds on the
// link-local IMDS endpoint. This is the normal on-prem / dev-laptop / non-cloud
// VM path — callers should treat it as a graceful degrade, not a failure.
var ErrNoCloudProvider = errors.New("no cloud provider detected")

// Provider names.
const (
	ProviderAWS   = "aws"
	ProviderGCP   = "gcp"
	ProviderAzure = "azure"
)

// Tag keys reported to alpacon-server. These match alpacon-server's
// _build_cloud_tags schema (cloud_plan/tasks/PHASE3D).
const (
	TagProvider         = "cloud:provider"
	TagInstanceID       = "cloud:instance_id"
	TagRegion           = "cloud:region"
	TagAvailabilityZone = "cloud:availability_zone"
	TagInstanceType     = "cloud:instance_type"
	TagNetworkID        = "cloud:network_id"
	TagAccountID        = "cloud:account_id"
)

// Metadata is the provider-agnostic snapshot of cloud-instance attributes
// that reconcile uses. Fields are best-effort: providers that cannot fetch
// a particular field leave it empty, and ToTags omits empty values.
type Metadata struct {
	Provider         string
	InstanceID       string
	Region           string
	AvailabilityZone string
	InstanceType     string
	NetworkID        string
	AccountID        string
}

// ToTags converts Metadata to the cloud:* tag map. Empty fields are omitted so
// they do not pollute Server.tags with blank values.
func (m *Metadata) ToTags() map[string]string {
	if m == nil {
		return nil
	}
	tags := make(map[string]string, 7)
	if m.Provider != "" {
		tags[TagProvider] = m.Provider
	}
	if m.InstanceID != "" {
		tags[TagInstanceID] = m.InstanceID
	}
	if m.Region != "" {
		tags[TagRegion] = m.Region
	}
	if m.AvailabilityZone != "" {
		tags[TagAvailabilityZone] = m.AvailabilityZone
	}
	if m.InstanceType != "" {
		tags[TagInstanceType] = m.InstanceType
	}
	if m.NetworkID != "" {
		tags[TagNetworkID] = m.NetworkID
	}
	if m.AccountID != "" {
		tags[TagAccountID] = m.AccountID
	}
	return tags
}

// Provider is the cloud-specific IMDS client.
//
// Probe is a short-timeout reachability check (typically the cheapest GET that
// proves the IMDS endpoint is the right provider). Fetch follows up with the
// full metadata read. Once Probe returns true, the host is treated as being
// on that provider — Detect never falls back to a different provider on Fetch
// failure, because IMDS endpoints are provider-specific and partial data is
// strictly better than wrong-provider data.
type Provider interface {
	Name() string
	Probe(ctx context.Context) bool
	Fetch(ctx context.Context) (*Metadata, error)
}
