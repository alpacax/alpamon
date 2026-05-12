package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Azure IMDS endpoint. Note that this lives on the same 169.254.169.254
// link-local address as AWS but requires the Metadata:true header and an
// api-version query param; AWS rejects requests with those, so the providers
// don't accidentally cross-respond.
const (
	azureDefaultBase  = "http://169.254.169.254"
	azureInstancePath = "/metadata/instance"
	azureAPIVersion   = "2021-02-01"

	azureHdrMetadata = "Metadata"
	azureHdrValue    = "true"

	azureResponseLimit = 32 * 1024 // Azure responses can be sizeable (full interface list)
)

const (
	azureProbeTimeout = 800 * time.Millisecond
	azureFetchTimeout = 2 * time.Second
)

type azureInstanceResponse struct {
	Compute struct {
		VMID           string `json:"vmId"`
		Location       string `json:"location"`
		Zone           string `json:"zone"`
		VMSize         string `json:"vmSize"`
		SubscriptionID string `json:"subscriptionId"`
	} `json:"compute"`
}

// AzureProvider implements Provider against Azure Instance Metadata Service.
type AzureProvider struct {
	base   string
	client *http.Client
}

// NewAzure returns an Azure provider pointed at the link-local IMDS endpoint.
func NewAzure() *AzureProvider { return NewAzureWithBase(azureDefaultBase) }

// NewAzureWithBase builds an Azure provider with an explicit base URL. Used
// by tests.
func NewAzureWithBase(base string) *AzureProvider {
	return &AzureProvider{
		base:   strings.TrimRight(base, "/"),
		client: newIMDSClient(azureFetchTimeout + 500*time.Millisecond),
	}
}

// Name implements Provider.
func (p *AzureProvider) Name() string { return ProviderAzure }

// Probe issues the standard /metadata/instance request. Success confirms
// Azure IMDS — AWS responds 401 here (no token) and GCP DNS won't resolve, so
// the discriminator is reliable.
func (p *AzureProvider) Probe(ctx context.Context) bool {
	probeCtx, cancel := context.WithTimeout(ctx, azureProbeTimeout)
	defer cancel()

	_, err := p.fetchInstance(probeCtx)
	return err == nil
}

// Fetch reads /metadata/instance and maps the response into Metadata. Azure
// IMDS exposes everything in a single JSON document, so one HTTP call covers
// all fields. NetworkID (VNet) is intentionally left empty: Azure IMDS exposes
// only subnet prefix, not the VNet name — getting VNet requires ARM API +
// managed identity, which is out of scope for V1.
func (p *AzureProvider) Fetch(ctx context.Context) (*Metadata, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, azureFetchTimeout)
	defer cancel()

	body, err := p.fetchInstance(fetchCtx)
	if err != nil {
		return &Metadata{Provider: ProviderAzure}, fmt.Errorf("azure imds instance: %w", err)
	}

	var resp azureInstanceResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return &Metadata{Provider: ProviderAzure}, fmt.Errorf("azure imds parse: %w", err)
	}

	return &Metadata{
		Provider:         ProviderAzure,
		InstanceID:       resp.Compute.VMID,
		Region:           resp.Compute.Location,
		AvailabilityZone: resp.Compute.Zone, // empty for zone-less deployments
		InstanceType:     resp.Compute.VMSize,
		AccountID:        resp.Compute.SubscriptionID,
		// NetworkID intentionally empty — see function-level comment.
	}, nil
}

func (p *AzureProvider) fetchInstance(ctx context.Context) ([]byte, error) {
	url := p.base + azureInstancePath + "?api-version=" + azureAPIVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(azureHdrMetadata, azureHdrValue)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("instance http %d", resp.StatusCode)
	}
	return readLimitedN(resp.Body, azureResponseLimit)
}
