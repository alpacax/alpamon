package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// AWS IMDSv2 endpoints. Production IMDS lives on the link-local address
// 169.254.169.254 — every EC2 instance has it routed locally.
const (
	awsDefaultBase = "http://169.254.169.254"

	awsTokenPath    = "/latest/api/token"
	awsDocumentPath = "/latest/dynamic/instance-identity/document"
	awsMACPath      = "/latest/meta-data/mac"
	awsVPCPathFmt   = "/latest/meta-data/network/interfaces/macs/%s/vpc-id"

	// awsTokenTTLHeader bounds the token lifetime. 6 hours is AWS's documented
	// maximum and is fine for a one-shot probe-then-fetch sequence.
	awsTokenTTLHeader = "21600"

	awsHdrTokenTTL = "X-aws-ec2-metadata-token-ttl-seconds"
	awsHdrToken    = "X-aws-ec2-metadata-token"

	awsResponseLimit = 8 * 1024 // 8 KB — IMDS payloads are tiny
)

// awsProbeTimeout / awsFetchTimeout bound individual HTTP attempts. Detect
// further bounds the whole probe+fetch sequence via ctx.
const (
	awsProbeTimeout = 800 * time.Millisecond
	awsFetchTimeout = 2 * time.Second
)

// awsIdentityDocument is the subset of the instance-identity document we care
// about. AWS keeps this stable across instance families.
type awsIdentityDocument struct {
	InstanceID       string `json:"instanceId"`
	Region           string `json:"region"`
	AvailabilityZone string `json:"availabilityZone"`
	InstanceType     string `json:"instanceType"`
	AccountID        string `json:"accountId"`
}

// AWSProvider implements Provider against EC2 IMDSv2.
type AWSProvider struct {
	base   string
	client *http.Client
}

// NewAWS returns an AWS provider targeting the link-local IMDS endpoint.
func NewAWS() *AWSProvider {
	return NewAWSWithBase(awsDefaultBase)
}

// NewAWSWithBase constructs an AWS provider against an arbitrary IMDS base URL.
// Tests inject an httptest server URL here.
func NewAWSWithBase(base string) *AWSProvider {
	return &AWSProvider{
		base:   strings.TrimRight(base, "/"),
		client: newIMDSClient(awsFetchTimeout + 500*time.Millisecond),
	}
}

// Name implements Provider.
func (p *AWSProvider) Name() string { return ProviderAWS }

// Probe attempts the IMDSv2 token PUT. Success confirms an AWS-style IMDS is
// reachable. Failures (network, timeout, non-2xx) are silent — Detect treats
// them as "not AWS, try next provider".
func (p *AWSProvider) Probe(ctx context.Context) bool {
	probeCtx, cancel := context.WithTimeout(ctx, awsProbeTimeout)
	defer cancel()

	_, err := p.fetchToken(probeCtx)
	return err == nil
}

// Fetch reads the instance-identity document and the primary ENI's VPC ID.
// If Probe-positive but Fetch encounters an error mid-read, we return whatever
// partial Metadata we managed to populate and let the caller log — we do NOT
// fall back to a different provider, because the host IS on AWS.
//
// On any failure path Fetch returns a non-nil *Metadata with at least
// Provider=aws set, matching the GCPProvider/AzureProvider contract so callers
// can call .ToTags() safely without nil-guarding the result.
func (p *AWSProvider) Fetch(ctx context.Context) (*Metadata, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, awsFetchTimeout)
	defer cancel()

	meta := &Metadata{Provider: ProviderAWS}

	token, err := p.fetchToken(fetchCtx)
	if err != nil {
		return meta, fmt.Errorf("aws imds token: %w", err)
	}

	doc, docErr := p.fetchDocument(fetchCtx, token)
	if docErr == nil {
		meta.InstanceID = doc.InstanceID
		meta.Region = doc.Region
		meta.AvailabilityZone = doc.AvailabilityZone
		meta.InstanceType = doc.InstanceType
		meta.AccountID = doc.AccountID
	}

	// VPC ID is best-effort: requires two extra hops (mac → vpc-id). If either
	// fails we leave NetworkID empty. The Server↔CloudInstance match uses
	// cloud:instance_id, so missing cloud:network_id does not break reconcile —
	// but we log at debug so field investigators can correlate "why is vpc empty"
	// with the real IMDS error.
	mac, macErr := p.fetchMAC(fetchCtx, token)
	switch {
	case macErr != nil:
		log.Debug().Err(macErr).Msg("aws imds mac fetch failed; cloud:network_id will be empty")
	case mac == "":
		log.Debug().Msg("aws imds returned empty mac; cloud:network_id will be empty")
	default:
		if vpc, vpcErr := p.fetchVPCID(fetchCtx, token, mac); vpcErr != nil {
			log.Debug().Err(vpcErr).Msg("aws imds vpc-id fetch failed; cloud:network_id will be empty")
		} else {
			meta.NetworkID = vpc
		}
	}

	// Only surface document error if it left us with no useful data beyond the
	// provider tag — gives callers a chance to log Warn but still report cloud:provider=aws.
	if docErr != nil && meta.InstanceID == "" {
		return meta, fmt.Errorf("aws identity document: %w", docErr)
	}
	return meta, nil
}

func (p *AWSProvider) fetchToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.base+awsTokenPath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(awsHdrTokenTTL, awsTokenTTLHeader)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token http %d", resp.StatusCode)
	}

	body, err := readLimitedN(resp.Body, awsResponseLimit)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(body))
	if tok == "" {
		return "", errors.New("empty token")
	}
	return tok, nil
}

func (p *AWSProvider) fetchDocument(ctx context.Context, token string) (*awsIdentityDocument, error) {
	body, err := p.imdsGet(ctx, token, awsDocumentPath)
	if err != nil {
		return nil, err
	}
	var doc awsIdentityDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse identity document: %w", err)
	}
	return &doc, nil
}

func (p *AWSProvider) fetchMAC(ctx context.Context, token string) (string, error) {
	body, err := p.imdsGet(ctx, token, awsMACPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func (p *AWSProvider) fetchVPCID(ctx context.Context, token, mac string) (string, error) {
	body, err := p.imdsGet(ctx, token, fmt.Sprintf(awsVPCPathFmt, mac))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func (p *AWSProvider) imdsGet(ctx context.Context, token, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(awsHdrToken, token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("imds %s http %d", path, resp.StatusCode)
	}
	return readLimitedN(resp.Body, awsResponseLimit)
}
