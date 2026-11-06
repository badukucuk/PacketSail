package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	dohEndpoint = "https://dns.google/resolve"
	dohAddress  = "8.8.8.8:443"
)

// Resolver performs IPv4 DNS lookups over HTTPS.
type Resolver struct {
	client   *http.Client
	endpoint string
}

// NewResolver creates a resolver that does not rely on system DNS to find the configured DNS-over-HTTPS server.
func NewResolver() *Resolver {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", dohAddress)
		},
		TLSHandshakeTimeout: 5 * time.Second,
	}

	return &Resolver{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		endpoint: dohEndpoint,
	}
}

// LookupIPv4 resolves a hostname to IPv4 addresses using DNS-over-HTTPS.
func (r *Resolver) LookupIPv4(ctx context.Context, hostname string) ([]net.IP, error) {
	if hostname == "" {
		return nil, fmt.Errorf("DNS hostname must not be empty")
	}

	query := url.Values{}
	query.Set("name", hostname)
	query.Set("type", "A")

	endpoint := r.endpoint + "?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create DNS request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform DNS request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNS server returned HTTP status %d", resp.StatusCode)
	}

	var result struct {
		Status int  `json:"Status"`
		TC     bool `json:"TC"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode DNS response: %w", err)
	}

	if result.TC {
		return nil, fmt.Errorf("DNS response was truncated")
	}

	if result.Status != 0 {
		return nil, fmt.Errorf("DNS lookup failed with response code %d", result.Status)
	}

	var addresses []net.IP

	for _, answer := range result.Answer {
		if answer.Type != 1 {
			continue
		}

		ip := net.ParseIP(answer.Data).To4()
		if ip != nil {
			addresses = append(addresses, ip)
		}
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses found for %q", hostname)
	}

	return addresses, nil
}
