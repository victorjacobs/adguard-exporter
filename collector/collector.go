package collector

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	processingTimeMsBuckets  = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	processingTimeSecBuckets = []float64{0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01}
	queryDetailsBuckets      = []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90}
)

// rollingCounter tracks a value from an API that can reset (e.g. rolling window)
// and synthesises a monotonically increasing total so rate() works correctly.
type rollingCounter struct {
	mu         sync.Mutex
	lastRaw    float64
	cumulative float64
	initialised bool
}

// update accepts the latest raw value from the API and returns the cumulative total.
// If the new value is less than the previous one a reset is assumed: the new value
// is added on top of the running total rather than replacing it.
func (r *rollingCounter) update(raw float64) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.initialised {
		r.cumulative = raw
		r.lastRaw = raw
		r.initialised = true
		return r.cumulative
	}
	if raw >= r.lastRaw {
		r.cumulative += raw - r.lastRaw
	} else {
		// Reset detected: add the new window's value on top
		r.cumulative += raw
	}
	r.lastRaw = raw
	return r.cumulative
}

// Collector implements prometheus.Collector for AdGuard Home.
type Collector struct {
	client *Client
	server string
	logger *slog.Logger

	// Rolling-window counters that can reset at the top of each hour
	queriesCounter        rollingCounter
	queriesBlockedCounter rollingCounter

	// Simple gauges
	running              *prometheus.Desc
	protectionEnabled    *prometheus.Desc
	dhcpEnabled          *prometheus.Desc
	avgProcessingTime    *prometheus.Desc
	queries              *prometheus.Desc
	queriesBlocked       *prometheus.Desc
	replacedSafebrowsing *prometheus.Desc
	replacedParental     *prometheus.Desc
	replacedSafesearch   *prometheus.Desc

	// Labeled gauges
	queriesDetails          *prometheus.Desc
	queryTypes              *prometheus.Desc
	topQueriedDomains       *prometheus.Desc
	topBlockedDomains       *prometheus.Desc
	topClients              *prometheus.Desc
	topUpstreams            *prometheus.Desc
	topUpstreamsAvgRespTime *prometheus.Desc

	// Histograms
	processingTimeMs        *prometheus.Desc
	processingTimeSec       *prometheus.Desc
	queriesDetailsHistogram *prometheus.Desc

	// Filtering metrics
	filteringEnabled *prometheus.Desc
	filterRulesCount *prometheus.Desc
	userRulesCount   *prometheus.Desc

	// TLS metrics
	tlsEnabled            *prometheus.Desc
	tlsCertificateExpiry  *prometheus.Desc
	tlsCertificateValid   *prometheus.Desc

	// DNS config metrics
	dnsCacheEnabled    *prometheus.Desc
	dnsCacheSizeBytes  *prometheus.Desc
	dnsRatelimit       *prometheus.Desc
	dnssecEnabled      *prometheus.Desc

	// Counter
	scrapeErrors *prometheus.CounterVec
}

// NewCollector creates a new AdGuard Home Prometheus collector.
func NewCollector(client *Client, server string, logger *slog.Logger) *Collector {
	c := &Collector{
		client: client,
		server: server,
		logger: logger,
	}

	serverLabel := []string{"server"}

	c.running = prometheus.NewDesc(
		"adguard_running",
		"Whether AdGuard Home is running (1 = running, 0 = not running).",
		serverLabel, nil,
	)
	c.protectionEnabled = prometheus.NewDesc(
		"adguard_protection_enabled",
		"Whether DNS protection is enabled (1 = enabled, 0 = disabled).",
		serverLabel, nil,
	)
	c.dhcpEnabled = prometheus.NewDesc(
		"adguard_dhcp_enabled",
		"Whether the DHCP server is enabled (1 = enabled, 0 = disabled).",
		serverLabel, nil,
	)
	c.avgProcessingTime = prometheus.NewDesc(
		"adguard_avg_processing_time_seconds",
		"Average DNS query processing time in seconds.",
		serverLabel, nil,
	)
	c.queries = prometheus.NewDesc(
		"adguard_queries",
		"Cumulative total DNS queries processed. Reset-detection applied to AdGuard's rolling window API.",
		serverLabel, nil,
	)
	c.queriesBlocked = prometheus.NewDesc(
		"adguard_queries_blocked",
		"Cumulative total DNS queries blocked. Reset-detection applied to AdGuard's rolling window API.",
		serverLabel, nil,
	)
	c.replacedSafebrowsing = prometheus.NewDesc(
		"adguard_replaced_safebrowsing",
		"Total number of queries replaced by safe browsing.",
		serverLabel, nil,
	)
	c.replacedParental = prometheus.NewDesc(
		"adguard_replaced_parental",
		"Total number of queries replaced by parental control.",
		serverLabel, nil,
	)
	c.replacedSafesearch = prometheus.NewDesc(
		"adguard_replaced_safesearch",
		"Total number of queries replaced by safe search.",
		serverLabel, nil,
	)

	c.queriesDetails = prometheus.NewDesc(
		"adguard_queries_details",
		"Number of DNS queries with detailed label breakdown.",
		[]string{"client", "client_name", "domain", "protocol", "reason", "server", "status", "type", "upstream"}, nil,
	)
	c.queryTypes = prometheus.NewDesc(
		"adguard_query_types",
		"Number of DNS queries by type.",
		[]string{"server", "type"}, nil,
	)
	c.topQueriedDomains = prometheus.NewDesc(
		"adguard_top_queried_domains",
		"Top queried domains.",
		[]string{"domain", "server"}, nil,
	)
	c.topBlockedDomains = prometheus.NewDesc(
		"adguard_top_blocked_domains",
		"Top blocked domains.",
		[]string{"domain", "server"}, nil,
	)
	c.topClients = prometheus.NewDesc(
		"adguard_top_clients",
		"Top clients by number of DNS queries.",
		[]string{"client", "server"}, nil,
	)
	c.topUpstreams = prometheus.NewDesc(
		"adguard_top_upstreams",
		"Top upstream DNS servers by number of queries.",
		[]string{"server", "upstream"}, nil,
	)
	c.topUpstreamsAvgRespTime = prometheus.NewDesc(
		"adguard_top_upstreams_avg_response_time_seconds",
		"Average response time of top upstream DNS servers in seconds.",
		[]string{"server", "upstream"}, nil,
	)

	c.processingTimeMs = prometheus.NewDesc(
		"adguard_processing_time_milliseconds",
		"Histogram of DNS query processing time in milliseconds.",
		[]string{"client", "server", "upstream"}, nil,
	)
	c.processingTimeSec = prometheus.NewDesc(
		"adguard_processing_time_seconds",
		"Histogram of DNS query processing time in seconds.",
		[]string{"client", "server", "upstream"}, nil,
	)
	c.queriesDetailsHistogram = prometheus.NewDesc(
		"adguard_queries_details_histogram",
		"Histogram of DNS queries with detailed label breakdown by processing time (ms).",
		[]string{"client_name", "protocol", "reason", "server", "status", "upstream", "user"}, nil,
	)

	c.filteringEnabled = prometheus.NewDesc(
		"adguard_filtering_enabled",
		"Whether DNS filtering is enabled (1 = enabled, 0 = disabled).",
		serverLabel, nil,
	)
	c.filterRulesCount = prometheus.NewDesc(
		"adguard_filter_rules_count",
		"Number of rules in a filter list.",
		[]string{"server", "id", "name", "url"}, nil,
	)
	c.userRulesCount = prometheus.NewDesc(
		"adguard_user_rules_count",
		"Number of user-defined filtering rules.",
		serverLabel, nil,
	)

	c.tlsEnabled = prometheus.NewDesc(
		"adguard_tls_enabled",
		"Whether TLS is enabled (1 = enabled, 0 = disabled).",
		serverLabel, nil,
	)
	c.tlsCertificateExpiry = prometheus.NewDesc(
		"adguard_tls_certificate_expiry_seconds",
		"Unix timestamp when the TLS certificate expires.",
		serverLabel, nil,
	)
	c.tlsCertificateValid = prometheus.NewDesc(
		"adguard_tls_certificate_valid",
		"Whether the TLS certificate is fully valid: cert, chain, key, and pair (1 = valid, 0 = invalid).",
		serverLabel, nil,
	)

	c.dnsCacheEnabled = prometheus.NewDesc(
		"adguard_dns_cache_enabled",
		"Whether DNS caching is enabled (1 = enabled, 0 = disabled).",
		serverLabel, nil,
	)
	c.dnsCacheSizeBytes = prometheus.NewDesc(
		"adguard_dns_cache_size_bytes",
		"Configured DNS cache size in bytes.",
		serverLabel, nil,
	)
	c.dnsRatelimit = prometheus.NewDesc(
		"adguard_dns_ratelimit",
		"Configured DNS rate limit (requests per second, 0 = unlimited).",
		serverLabel, nil,
	)
	c.dnssecEnabled = prometheus.NewDesc(
		"adguard_dns_dnssec_enabled",
		"Whether DNSSEC is enabled (1 = enabled, 0 = disabled).",
		serverLabel, nil,
	)

	c.scrapeErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "adguard_scrape_errors_total",
		Help: "Total number of errors scraping AdGuard Home.",
	}, []string{"server"})

	return c
}

// Describe sends descriptors of all metrics to the channel.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.running
	ch <- c.protectionEnabled
	ch <- c.dhcpEnabled
	ch <- c.avgProcessingTime
	ch <- c.queries
	ch <- c.queriesBlocked
	ch <- c.replacedSafebrowsing
	ch <- c.replacedParental
	ch <- c.replacedSafesearch
	ch <- c.queriesDetails
	ch <- c.queryTypes
	ch <- c.topQueriedDomains
	ch <- c.topBlockedDomains
	ch <- c.topClients
	ch <- c.topUpstreams
	ch <- c.topUpstreamsAvgRespTime
	ch <- c.processingTimeMs
	ch <- c.processingTimeSec
	ch <- c.queriesDetailsHistogram
	ch <- c.filteringEnabled
	ch <- c.filterRulesCount
	ch <- c.userRulesCount
	ch <- c.tlsEnabled
	ch <- c.tlsCertificateExpiry
	ch <- c.tlsCertificateValid
	ch <- c.dnsCacheEnabled
	ch <- c.dnsCacheSizeBytes
	ch <- c.dnsRatelimit
	ch <- c.dnssecEnabled
	c.scrapeErrors.Describe(ch)
}

// Collect fetches metrics from AdGuard Home and sends them to the channel.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.scrapeErrors.Collect(ch)

	if err := c.collectStatus(ch); err != nil {
		c.logger.Error("failed to collect status", "err", err)
		c.scrapeErrors.WithLabelValues(c.server).Inc()
	}
	if err := c.collectStats(ch); err != nil {
		c.logger.Error("failed to collect stats", "err", err)
		c.scrapeErrors.WithLabelValues(c.server).Inc()
	}
	if err := c.collectQueryLog(ch); err != nil {
		c.logger.Error("failed to collect query log", "err", err)
		c.scrapeErrors.WithLabelValues(c.server).Inc()
	}
	if err := c.collectFiltering(ch); err != nil {
		c.logger.Error("failed to collect filtering status", "err", err)
		c.scrapeErrors.WithLabelValues(c.server).Inc()
	}
	if err := c.collectTLS(ch); err != nil {
		c.logger.Error("failed to collect TLS status", "err", err)
		c.scrapeErrors.WithLabelValues(c.server).Inc()
	}
	if err := c.collectDNSInfo(ch); err != nil {
		c.logger.Error("failed to collect DNS info", "err", err)
		c.scrapeErrors.WithLabelValues(c.server).Inc()
	}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (c *Collector) collectStatus(ch chan<- prometheus.Metric) error {
	status, err := c.client.GetStatus()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.running, prometheus.GaugeValue, boolToFloat(status.Running), c.server)
	ch <- prometheus.MustNewConstMetric(c.protectionEnabled, prometheus.GaugeValue, boolToFloat(status.ProtectionEnabled), c.server)

	dhcpEnabled := 0.0
	if dhcp, err := c.client.GetDHCPStatus(); err == nil {
		dhcpEnabled = boolToFloat(dhcp.Enabled)
	} else {
		c.logger.Warn("failed to fetch DHCP status, defaulting to 0", "err", err)
	}
	ch <- prometheus.MustNewConstMetric(c.dhcpEnabled, prometheus.GaugeValue, dhcpEnabled, c.server)

	return nil
}

func (c *Collector) collectStats(ch chan<- prometheus.Metric) error {
	stats, err := c.client.GetStats()
	if err != nil {
		return err
	}

	// avg_processing_time from API is in milliseconds, convert to seconds
	ch <- prometheus.MustNewConstMetric(c.avgProcessingTime, prometheus.GaugeValue, stats.AvgProcessingTime/1000.0, c.server)

	// Use reset-aware counters so hourly window resets don't produce spikes in rate()
	ch <- prometheus.MustNewConstMetric(c.queries, prometheus.GaugeValue, c.queriesCounter.update(float64(stats.NumDNSQueries)), c.server)
	ch <- prometheus.MustNewConstMetric(c.queriesBlocked, prometheus.GaugeValue, c.queriesBlockedCounter.update(float64(stats.NumBlockedFiltering)), c.server)
	ch <- prometheus.MustNewConstMetric(c.replacedSafebrowsing, prometheus.GaugeValue, float64(stats.NumReplacedSafebrowsing), c.server)
	ch <- prometheus.MustNewConstMetric(c.replacedParental, prometheus.GaugeValue, float64(stats.NumReplacedParental), c.server)
	ch <- prometheus.MustNewConstMetric(c.replacedSafesearch, prometheus.GaugeValue, float64(stats.NumReplacedSafesearch), c.server)

	for _, entry := range stats.TopQueriedDomains {
		for domain, count := range entry {
			ch <- prometheus.MustNewConstMetric(c.topQueriedDomains, prometheus.GaugeValue, float64(count), domain, c.server)
		}
	}
	for _, entry := range stats.TopBlockedDomains {
		for domain, count := range entry {
			ch <- prometheus.MustNewConstMetric(c.topBlockedDomains, prometheus.GaugeValue, float64(count), domain, c.server)
		}
	}
	for _, entry := range stats.TopClients {
		for client, count := range entry {
			ch <- prometheus.MustNewConstMetric(c.topClients, prometheus.GaugeValue, float64(count), client, c.server)
		}
	}
	for _, entry := range stats.TopUpstreamsResponses {
		for upstream, count := range entry {
			ch <- prometheus.MustNewConstMetric(c.topUpstreams, prometheus.GaugeValue, float64(count), c.server, upstream)
		}
	}
	for _, entry := range stats.TopUpstreamsAvgTime {
		for upstream, avg := range entry {
			ch <- prometheus.MustNewConstMetric(c.topUpstreamsAvgRespTime, prometheus.GaugeValue, avg, c.server, upstream)
		}
	}
	for qtype, count := range stats.QueryTypes {
		ch <- prometheus.MustNewConstMetric(c.queryTypes, prometheus.GaugeValue, count, c.server, qtype)
	}

	return nil
}

// histogramKey groups query log entries for histogram aggregation.
type histogramKey struct {
	client   string
	upstream string
}

type detailHistogramKey struct {
	clientName string
	protocol   string
	reason     string
	status     string
	upstream   string
	user       string
}

type detailKey struct {
	client     string
	clientName string
	domain     string
	protocol   string
	reason     string
	status     string
	qtype      string
	upstream   string
}

type histData struct {
	// cumulative bucket counts indexed by position in the buckets slice
	buckets map[float64]uint64
	sum     float64
	count   uint64
}

func newHistData(bounds []float64) *histData {
	m := make(map[float64]uint64, len(bounds))
	for _, b := range bounds {
		m[b] = 0
	}
	return &histData{buckets: m}
}

func (h *histData) observe(value float64, bounds []float64) {
	for _, bound := range bounds {
		if value <= bound {
			h.buckets[bound]++
		}
	}
	h.sum += value
	h.count++
}

func (c *Collector) collectQueryLog(ch chan<- prometheus.Metric) error {
	ql, err := c.client.GetQueryLog()
	if err != nil {
		return err
	}

	msHists := make(map[histogramKey]*histData)
	secHists := make(map[histogramKey]*histData)
	detailHists := make(map[detailHistogramKey]*histData)
	detailCounts := make(map[detailKey]float64)

	for _, entry := range ql.Data {
		elapsedMs := entry.ElapsedMs
		elapsedSec := elapsedMs / 1000.0
		upstream := entry.Upstream
		client := entry.Client
		clientName := entry.ClientName
		domain := entry.Question.Name
		qtype := entry.Question.Type
		reason := entry.Reason
		status := entry.Status
		if status == "" {
			status = reason
		}
		protocol := protocolFromUpstream(upstream)

		// adguard_queries_details
		dk := detailKey{
			client:     client,
			clientName: clientName,
			domain:     domain,
			protocol:   protocol,
			reason:     reason,
			status:     status,
			qtype:      qtype,
			upstream:   upstream,
		}
		detailCounts[dk]++

		// Processing time histograms (ms)
		hk := histogramKey{client: client, upstream: upstream}
		if _, ok := msHists[hk]; !ok {
			msHists[hk] = newHistData(processingTimeMsBuckets)
		}
		msHists[hk].observe(elapsedMs, processingTimeMsBuckets)

		// Processing time histograms (seconds)
		if _, ok := secHists[hk]; !ok {
			secHists[hk] = newHistData(processingTimeSecBuckets)
		}
		secHists[hk].observe(elapsedSec, processingTimeSecBuckets)

		// Queries details histogram
		dhk := detailHistogramKey{
			clientName: clientName,
			protocol:   protocol,
			reason:     reason,
			status:     status,
			upstream:   upstream,
			user:       client,
		}
		if _, ok := detailHists[dhk]; !ok {
			detailHists[dhk] = newHistData(queryDetailsBuckets)
		}
		detailHists[dhk].observe(elapsedMs, queryDetailsBuckets)
	}

	// Emit adguard_queries_details
	for dk, count := range detailCounts {
		ch <- prometheus.MustNewConstMetric(
			c.queriesDetails, prometheus.GaugeValue, count,
			dk.client, dk.clientName, dk.domain, dk.protocol, dk.reason,
			c.server, dk.status, dk.qtype, dk.upstream,
		)
	}

	// Emit processing time ms histograms
	for hk, h := range msHists {
		ch <- prometheus.MustNewConstHistogram(
			c.processingTimeMs,
			h.count, h.sum, h.buckets,
			hk.client, c.server, hk.upstream,
		)
	}

	// Emit processing time seconds histograms
	for hk, h := range secHists {
		ch <- prometheus.MustNewConstHistogram(
			c.processingTimeSec,
			h.count, h.sum, h.buckets,
			hk.client, c.server, hk.upstream,
		)
	}

	// Emit queries details histograms
	for dhk, dh := range detailHists {
		ch <- prometheus.MustNewConstHistogram(
			c.queriesDetailsHistogram,
			dh.count, dh.sum, dh.buckets,
			dhk.clientName, dhk.protocol, dhk.reason, c.server,
			dhk.status, dhk.upstream, dhk.user,
		)
	}

	return nil
}

func (c *Collector) collectFiltering(ch chan<- prometheus.Metric) error {
	f, err := c.client.GetFilteringStatus()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.filteringEnabled, prometheus.GaugeValue, boolToFloat(f.Enabled), c.server)
	ch <- prometheus.MustNewConstMetric(c.userRulesCount, prometheus.GaugeValue, float64(len(f.UserRules)), c.server)

	for _, filter := range f.Filters {
		ch <- prometheus.MustNewConstMetric(
			c.filterRulesCount, prometheus.GaugeValue, float64(filter.RulesCount),
			c.server, fmt.Sprintf("%d", filter.ID), filter.Name, filter.URL,
		)
	}
	return nil
}

func (c *Collector) collectTLS(ch chan<- prometheus.Metric) error {
	t, err := c.client.GetTLSStatus()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.tlsEnabled, prometheus.GaugeValue, boolToFloat(t.Enabled), c.server)

	if t.Enabled && t.NotAfter != "" {
		if expiry, err := time.Parse(time.RFC3339, t.NotAfter); err == nil {
			ch <- prometheus.MustNewConstMetric(c.tlsCertificateExpiry, prometheus.GaugeValue, float64(expiry.Unix()), c.server)
		} else {
			c.logger.Warn("failed to parse TLS certificate expiry", "not_after", t.NotAfter, "err", err)
		}
		valid := t.ValidCert && t.ValidChain && t.ValidKey && t.ValidPair
		ch <- prometheus.MustNewConstMetric(c.tlsCertificateValid, prometheus.GaugeValue, boolToFloat(valid), c.server)
	}

	return nil
}

func (c *Collector) collectDNSInfo(ch chan<- prometheus.Metric) error {
	d, err := c.client.GetDNSInfo()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.dnsCacheEnabled, prometheus.GaugeValue, boolToFloat(d.CacheEnabled), c.server)
	ch <- prometheus.MustNewConstMetric(c.dnsCacheSizeBytes, prometheus.GaugeValue, float64(d.CacheSize), c.server)
	ch <- prometheus.MustNewConstMetric(c.dnsRatelimit, prometheus.GaugeValue, float64(d.Ratelimit), c.server)
	ch <- prometheus.MustNewConstMetric(c.dnssecEnabled, prometheus.GaugeValue, boolToFloat(d.DNSSECEnabled), c.server)

	return nil
}

// protocolFromUpstream infers the protocol from the upstream address.
func protocolFromUpstream(upstream string) string {
	if len(upstream) == 0 {
		return "blocked"
	}
	switch {
	case len(upstream) >= 6 && upstream[:6] == "https:":
		return "doh"
	case len(upstream) >= 4 && upstream[:4] == "tls:":
		return "dot"
	case len(upstream) >= 5 && upstream[:5] == "quic:":
		return "doq"
	default:
		return "udp"
	}
}
