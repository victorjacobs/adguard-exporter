package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an AdGuard Home API client.
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

// NewClient creates a new AdGuard Home API client.
func NewClient(baseURL, username, password string) *Client {
	return &Client{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) get(path string, out interface{}) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d for %s", resp.StatusCode, path)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("unmarshalling response: %w", err)
	}
	return nil
}

// GetStatus fetches the AdGuard Home status.
func (c *Client) GetStatus() (*StatusResponse, error) {
	var status StatusResponse
	if err := c.get("/control/status", &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// GetDHCPStatus fetches the AdGuard Home DHCP server status.
func (c *Client) GetDHCPStatus() (*DHCPStatusResponse, error) {
	var dhcp DHCPStatusResponse
	if err := c.get("/control/dhcp/status", &dhcp); err != nil {
		return nil, err
	}
	return &dhcp, nil
}

// GetStats fetches the AdGuard Home statistics.
func (c *Client) GetStats() (*StatsResponse, error) {
	var stats StatsResponse
	if err := c.get("/control/stats", &stats); err != nil {
		return nil, err
	}
	return &stats, nil
}

// GetFilteringStatus fetches the AdGuard Home filtering configuration.
func (c *Client) GetFilteringStatus() (*FilteringStatusResponse, error) {
	var f FilteringStatusResponse
	if err := c.get("/control/filtering/status", &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// GetTLSStatus fetches the AdGuard Home TLS configuration.
func (c *Client) GetTLSStatus() (*TLSStatusResponse, error) {
	var t TLSStatusResponse
	if err := c.get("/control/tls/status", &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// GetDNSInfo fetches the AdGuard Home DNS configuration.
func (c *Client) GetDNSInfo() (*DNSInfoResponse, error) {
	var d DNSInfoResponse
	if err := c.get("/control/dns_info", &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// GetQueryLog fetches the AdGuard Home query log.
func (c *Client) GetQueryLog() (*QueryLogResponse, error) {
	var log QueryLogResponse
	if err := c.get("/control/querylog?limit=1000", &log); err != nil {
		return nil, err
	}
	return &log, nil
}
