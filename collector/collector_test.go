package collector

import (
	"errors"
	"io"
	"log/slog"
	"math"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/prometheus/client_golang/prometheus"
)

type stubClient struct {
	status             *StatusResponse
	statusErr          error
	dhcpStatus         *DHCPStatusResponse
	dhcpStatusErr      error
	stats              *StatsResponse
	statsErr           error
	queryLog           *QueryLogResponse
	queryLogErr        error
	filteringStatus    *FilteringStatusResponse
	filteringStatusErr error
	tlsStatus          *TLSStatusResponse
	tlsStatusErr       error
	dnsInfo            *DNSInfoResponse
	dnsInfoErr         error
}

var _ APIClient = &stubClient{}

func (c *stubClient) GetStatus() (*StatusResponse, error) {
	return c.status, c.statusErr
}

func (c *stubClient) GetDHCPStatus() (*DHCPStatusResponse, error) {
	return c.dhcpStatus, c.dhcpStatusErr
}

func (c *stubClient) GetStats() (*StatsResponse, error) {
	return c.stats, c.statsErr
}

func (c *stubClient) GetQueryLog() (*QueryLogResponse, error) {
	return c.queryLog, c.queryLogErr
}

func (c *stubClient) GetFilteringStatus() (*FilteringStatusResponse, error) {
	return c.filteringStatus, c.filteringStatusErr
}

func (c *stubClient) GetTLSStatus() (*TLSStatusResponse, error) {
	return c.tlsStatus, c.tlsStatusErr
}

func (c *stubClient) GetDNSInfo() (*DNSInfoResponse, error) {
	return c.dnsInfo, c.dnsInfoErr
}

func successfulStubClient() *stubClient {
	return &stubClient{
		status:     &StatusResponse{Running: true, ProtectionEnabled: true},
		dhcpStatus: &DHCPStatusResponse{Enabled: true},
		stats: &StatsResponse{
			NumDNSQueries:         100,
			NumBlockedFiltering:   20,
			AvgProcessingTime:     0.025,
			TopQueriedDomains:     []map[string]int{{"example.com": 10}},
			TopBlockedDomains:     []map[string]int{{"ads.example": 5}},
			TopClients:            []map[string]int{{"192.0.2.1": 10}},
			TopUpstreamsResponses: []map[string]int{{"tls://dns.example": 10}},
			TopUpstreamsAvgTime:   []map[string]float64{{"tls://dns.example": 0.02}},
			QueryTypes:            map[string]float64{"A": 8},
		},
		queryLog: &QueryLogResponse{
			Data: []QueryLogEntry{{
				Question:       Question{Name: "example.com", Type: "A"},
				Client:         "192.0.2.1",
				ClientInfo:     ClientInfo{Name: "laptop"},
				ClientProtocol: "doh",
				Upstream:       "tls://dns.example",
				ElapsedMs:      "1.25",
				Reason:         "NotFilteredNotFound",
				Status:         "NOERROR",
			}},
		},
		filteringStatus: &FilteringStatusResponse{
			Enabled: true,
			Filters: []Filter{{
				ID: 1, Name: "blocklist", URL: "https://example.com/block.txt", RulesCount: 10,
			}},
			WhitelistFilters: []Filter{{
				ID: 2, Name: "allowlist", URL: "https://example.com/allow.txt", RulesCount: 3,
			}},
			UserRules: []string{"||ads.example^"},
		},
		tlsStatus: &TLSStatusResponse{
			Enabled: true,
		},
		dnsInfo: &DNSInfoResponse{
			CacheEnabled:  true,
			CacheSize:     4 << 20,
			Ratelimit:     20,
			DNSSECEnabled: true,
		},
	}
}

func TestCollectorKeepsQueryAndClientStatisticsMonotonic(t *testing.T) {
	client := successfulStubClient()
	registry := newTestRegistry(t, client)

	metrics := gatherMetrics(t, registry)
	assertGauge(t, metrics, "adguard_queries", map[string]string{"server": "https://adguard.example"}, 100)
	assertGauge(t, metrics, "adguard_top_clients", map[string]string{
		"server": "https://adguard.example",
		"client": "192.0.2.1",
	}, 10)
	assertGauge(t, metrics, "adguard_queries_details", map[string]string{
		"server":   "https://adguard.example",
		"protocol": "doh",
		"upstream": "tls://dns.example",
	}, 1)
	assertGauge(t, metrics, "adguard_tls_certificate_valid", map[string]string{
		"server": "https://adguard.example",
	}, 0)
	assertGauge(t, metrics, "adguard_filter_rules_count", map[string]string{
		"server": "https://adguard.example",
		"id":     "2",
		"name":   "allowlist",
	}, 3)
	assertCounter(t, metrics, "adguard_scrape_errors_total", map[string]string{
		"server": "https://adguard.example",
	}, 0)

	client.stats.NumDNSQueries = 80
	client.stats.TopClients[0]["192.0.2.1"] = 7
	metrics = gatherMetrics(t, registry)
	assertGauge(t, metrics, "adguard_queries", map[string]string{"server": "https://adguard.example"}, 100)
	assertGauge(t, metrics, "adguard_top_clients", map[string]string{
		"server": "https://adguard.example",
		"client": "192.0.2.1",
	}, 10)

	client.stats.NumDNSQueries = 85
	client.stats.TopClients[0]["192.0.2.1"] = 9
	metrics = gatherMetrics(t, registry)
	assertGauge(t, metrics, "adguard_queries", map[string]string{"server": "https://adguard.example"}, 105)
	assertGauge(t, metrics, "adguard_top_clients", map[string]string{
		"server": "https://adguard.example",
		"client": "192.0.2.1",
	}, 12)
}

func TestCollectorKeepsValidQueryLogEntries(t *testing.T) {
	client := successfulStubClient()
	client.queryLog.Data = append(client.queryLog.Data, QueryLogEntry{
		ElapsedMs: "not-a-number",
	})

	metrics := gatherMetrics(t, newTestRegistry(t, client))

	assertGauge(t, metrics, "adguard_queries_details", map[string]string{
		"server": "https://adguard.example",
		"domain": "example.com",
	}, 1)
	assertCounter(t, metrics, "adguard_scrape_errors_total", map[string]string{
		"server": "https://adguard.example",
	}, 1)
}

func TestCollectorCountsEveryFailedEndpointOnCurrentScrape(t *testing.T) {
	endpointError := errors.New("endpoint unavailable")
	client := &stubClient{
		statusErr:          endpointError,
		dhcpStatusErr:      endpointError,
		statsErr:           endpointError,
		queryLogErr:        endpointError,
		filteringStatusErr: endpointError,
		tlsStatusErr:       endpointError,
		dnsInfoErr:         endpointError,
	}

	metrics := gatherMetrics(t, newTestRegistry(t, client))

	assertCounter(t, metrics, "adguard_scrape_errors_total", map[string]string{
		"server": "https://adguard.example",
	}, 7)
	if _, exists := metrics["adguard_dhcp_enabled"]; exists {
		t.Error("adguard_dhcp_enabled was emitted for a failed DHCP request")
	}
}

func TestParseElapsedMilliseconds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		want    float64
		wantErr bool
	}{
		{name: "zero", value: "0", want: 0},
		{name: "fraction", value: "0.098403", want: 0.098403},
		{name: "negative", value: "-1", wantErr: true},
		{name: "NaN", value: "NaN", wantErr: true},
		{name: "positive infinity", value: "+Inf", wantErr: true},
		{name: "invalid", value: "slow", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseElapsedMilliseconds(test.value)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseElapsedMilliseconds(%q) returned no error", test.value)
				}

				return
			}
			if err != nil {
				t.Fatalf("parseElapsedMilliseconds(%q) error = %v", test.value, err)
			}
			if math.Abs(got-test.want) > 1e-12 {
				t.Errorf("parseElapsedMilliseconds(%q) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}

func TestRollingCounter(t *testing.T) {
	t.Parallel()

	var counter rollingCounter
	tests := []struct {
		raw  float64
		want float64
	}{
		{raw: 100, want: 100},
		{raw: 120, want: 120},
		{raw: 90, want: 120},
		{raw: 95, want: 125},
		{raw: 95, want: 125},
	}

	for _, test := range tests {
		if got := counter.update(test.raw); got != test.want {
			t.Errorf("update(%v) = %v, want %v", test.raw, got, test.want)
		}
	}
}

func newTestRegistry(t *testing.T, client APIClient) *prometheus.Registry {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := prometheus.NewRegistry()
	if err := registry.Register(NewCollector(client, "https://adguard.example", logger)); err != nil {
		t.Fatalf("register collector: %v", err)
	}

	return registry
}

func gatherMetrics(t *testing.T, registry *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	metrics := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		metrics[family.GetName()] = family
	}

	return metrics
}

func assertGauge(
	t *testing.T,
	metrics map[string]*dto.MetricFamily,
	name string,
	labels map[string]string,
	want float64,
) {
	t.Helper()

	metric := findMetric(t, metrics, name, labels)
	if got := metric.GetGauge().GetValue(); got != want {
		t.Errorf("%s%v = %v, want %v", name, labels, got, want)
	}
}

func assertCounter(
	t *testing.T,
	metrics map[string]*dto.MetricFamily,
	name string,
	labels map[string]string,
	want float64,
) {
	t.Helper()

	metric := findMetric(t, metrics, name, labels)
	if got := metric.GetCounter().GetValue(); got != want {
		t.Errorf("%s%v = %v, want %v", name, labels, got, want)
	}
}

func findMetric(
	t *testing.T,
	metrics map[string]*dto.MetricFamily,
	name string,
	labels map[string]string,
) *dto.Metric {
	t.Helper()

	family, exists := metrics[name]
	if !exists {
		t.Fatalf("metric family %q was not emitted", name)
	}

	for _, metric := range family.Metric {
		if metricHasLabels(metric, labels) {
			return metric
		}
	}

	t.Fatalf("metric family %q has no metric with labels %v", name, labels)

	return nil
}

func metricHasLabels(metric *dto.Metric, labels map[string]string) bool {
	matched := 0
	for _, pair := range metric.Label {
		value, exists := labels[pair.GetName()]
		if exists && value == pair.GetValue() {
			matched++
		}
	}

	return matched == len(labels)
}
