package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	requestTimeout  = 30 * time.Second
	maxResponseSize = 16 << 20
)

// Client is an AdGuard Home API client.
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

var _ APIClient = &Client{}

// NewClient creates a new AdGuard Home API client.
func NewClient(baseURL, username, password string) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse AdGuard URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("parse AdGuard URL: unsupported scheme %q", parsedURL.Scheme)
	}
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("parse AdGuard URL: host is required")
	}
	if parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, fmt.Errorf("parse AdGuard URL: query and fragment are not supported")
	}

	return &Client{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: requestTimeout,
		},
	}, nil
}

func (c *Client) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		if readErr != nil {
			return fmt.Errorf("request %s: unexpected status %s (read response: %w)", path, resp.Status, readErr)
		}

		return fmt.Errorf("request %s: unexpected status %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return fmt.Errorf("read response from %s: %w", path, err)
	}
	if len(body) > maxResponseSize {
		return fmt.Errorf("read response from %s: body exceeds %d bytes", path, maxResponseSize)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response from %s: %w", path, err)
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
	var filtering FilteringStatusResponse
	if err := c.get("/control/filtering/status", &filtering); err != nil {
		return nil, err
	}

	return &filtering, nil
}

// GetTLSStatus fetches the AdGuard Home TLS configuration.
func (c *Client) GetTLSStatus() (*TLSStatusResponse, error) {
	var tls TLSStatusResponse
	if err := c.get("/control/tls/status", &tls); err != nil {
		return nil, err
	}

	return &tls, nil
}

// GetDNSInfo fetches the AdGuard Home DNS configuration.
func (c *Client) GetDNSInfo() (*DNSInfoResponse, error) {
	var dnsInfo DNSInfoResponse
	if err := c.get("/control/dns_info", &dnsInfo); err != nil {
		return nil, err
	}

	return &dnsInfo, nil
}

// GetQueryLog fetches the AdGuard Home query log.
func (c *Client) GetQueryLog() (*QueryLogResponse, error) {
	var queryLog QueryLogResponse
	if err := c.get("/control/querylog?limit=1000", &queryLog); err != nil {
		return nil, err
	}

	return &queryLog, nil
}
