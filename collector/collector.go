package collector

import (
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Collector struct {
	client       APIClient
	server       string
	logger       *slog.Logger
	metrics      metricDescriptors
	scrapeErrors *prometheus.CounterVec

	statsMu               sync.Mutex
	queriesCounter        rollingCounter
	queriesBlockedCounter rollingCounter
	clientCounters        map[string]*rollingCounter
}

var _ prometheus.Collector = &Collector{}

func NewCollector(client APIClient, server string, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}

	collector := &Collector{
		client:         client,
		server:         server,
		logger:         logger,
		metrics:        newMetricDescriptors(),
		clientCounters: make(map[string]*rollingCounter),
		scrapeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "scrape_errors_total",
			Help:      "Total number of errors scraping AdGuard Home.",
		}, []string{"server"}),
	}
	collector.scrapeErrors.WithLabelValues(server)

	return collector
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	c.metrics.describe(ch)
	c.scrapeErrors.Describe(ch)
}

type scrapeCollector struct {
	name    string
	collect func(chan<- prometheus.Metric) error
}

type scrapeResult struct {
	name string
	err  error
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	collectors := []scrapeCollector{
		{name: "status", collect: c.collectStatus},
		{name: "DHCP status", collect: c.collectDHCPStatus},
		{name: "statistics", collect: c.collectStats},
		{name: "query log", collect: c.collectQueryLog},
		{name: "filtering status", collect: c.collectFiltering},
		{name: "TLS status", collect: c.collectTLS},
		{name: "DNS configuration", collect: c.collectDNSInfo},
	}

	results := make(chan scrapeResult, len(collectors))
	var waitGroup sync.WaitGroup
	waitGroup.Add(len(collectors))

	for _, collector := range collectors {
		go func() {
			defer waitGroup.Done()

			if err := collector.collect(ch); err != nil {
				results <- scrapeResult{name: collector.name, err: err}
			}
		}()
	}

	waitGroup.Wait()
	close(results)

	for result := range results {
		c.logger.Error("failed to collect AdGuard metrics", "collector", result.name, "server", c.server, "err", result.err)
		c.scrapeErrors.WithLabelValues(c.server).Inc()
	}

	c.scrapeErrors.Collect(ch)
}

func (c *Collector) collectStatus(ch chan<- prometheus.Metric) error {
	status, err := c.client.GetStatus()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.metrics.running, prometheus.GaugeValue, boolToFloat(status.Running), c.server)
	ch <- prometheus.MustNewConstMetric(c.metrics.protectionEnabled, prometheus.GaugeValue, boolToFloat(status.ProtectionEnabled), c.server)

	return nil
}

func (c *Collector) collectDHCPStatus(ch chan<- prometheus.Metric) error {
	status, err := c.client.GetDHCPStatus()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.metrics.dhcpEnabled, prometheus.GaugeValue, boolToFloat(status.Enabled), c.server)

	return nil
}

func (c *Collector) collectStats(ch chan<- prometheus.Metric) error {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()

	stats, err := c.client.GetStats()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.metrics.avgProcessingTime, prometheus.GaugeValue, stats.AvgProcessingTime, c.server)
	ch <- prometheus.MustNewConstMetric(c.metrics.queries, prometheus.GaugeValue, c.queriesCounter.update(float64(stats.NumDNSQueries)), c.server)
	ch <- prometheus.MustNewConstMetric(c.metrics.queriesBlocked, prometheus.GaugeValue, c.queriesBlockedCounter.update(float64(stats.NumBlockedFiltering)), c.server)
	ch <- prometheus.MustNewConstMetric(c.metrics.replacedSafebrowsing, prometheus.GaugeValue, float64(stats.NumReplacedSafebrowsing), c.server)
	ch <- prometheus.MustNewConstMetric(c.metrics.replacedParental, prometheus.GaugeValue, float64(stats.NumReplacedParental), c.server)
	ch <- prometheus.MustNewConstMetric(c.metrics.replacedSafesearch, prometheus.GaugeValue, float64(stats.NumReplacedSafesearch), c.server)

	emitTopEntries(ch, c.metrics.topQueriedDomains, c.server, stats.TopQueriedDomains)
	emitTopEntries(ch, c.metrics.topBlockedDomains, c.server, stats.TopBlockedDomains)
	c.emitTopClients(ch, stats.TopClients)
	emitTopEntries(ch, c.metrics.topUpstreams, c.server, stats.TopUpstreamsResponses)
	emitTopEntries(ch, c.metrics.topUpstreamsAvgResponseTime, c.server, stats.TopUpstreamsAvgTime)

	for queryType, count := range stats.QueryTypes {
		ch <- prometheus.MustNewConstMetric(c.metrics.queryTypes, prometheus.GaugeValue, count, c.server, queryType)
	}

	return nil
}

func (c *Collector) emitTopClients(ch chan<- prometheus.Metric, entries []map[string]int) {
	for _, entry := range entries {
		for client, rawCount := range entry {
			counter, exists := c.clientCounters[client]
			if !exists {
				counter = &rollingCounter{}
				c.clientCounters[client] = counter
			}

			ch <- prometheus.MustNewConstMetric(
				c.metrics.topClients,
				prometheus.GaugeValue,
				counter.update(float64(rawCount)),
				c.server,
				client,
			)
		}
	}
}

func emitTopEntries[T ~int | ~float64](
	ch chan<- prometheus.Metric,
	descriptor *prometheus.Desc,
	server string,
	entries []map[string]T,
) {
	for _, entry := range entries {
		for label, value := range entry {
			ch <- prometheus.MustNewConstMetric(descriptor, prometheus.GaugeValue, float64(value), server, label)
		}
	}
}

func (c *Collector) collectFiltering(ch chan<- prometheus.Metric) error {
	status, err := c.client.GetFilteringStatus()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.metrics.filteringEnabled, prometheus.GaugeValue, boolToFloat(status.Enabled), c.server)
	ch <- prometheus.MustNewConstMetric(c.metrics.userRulesCount, prometheus.GaugeValue, float64(len(status.UserRules)), c.server)

	emitFilters(ch, c.metrics.filterRulesCount, c.server, status.Filters)
	emitFilters(ch, c.metrics.filterRulesCount, c.server, status.WhitelistFilters)

	return nil
}

func emitFilters(ch chan<- prometheus.Metric, descriptor *prometheus.Desc, server string, filters []Filter) {
	for _, filter := range filters {
		ch <- prometheus.MustNewConstMetric(
			descriptor,
			prometheus.GaugeValue,
			float64(filter.RulesCount),
			server,
			strconv.FormatInt(filter.ID, 10),
			filter.Name,
			filter.URL,
		)
	}
}

func (c *Collector) collectTLS(ch chan<- prometheus.Metric) error {
	status, err := c.client.GetTLSStatus()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.metrics.tlsEnabled, prometheus.GaugeValue, boolToFloat(status.Enabled), c.server)
	if !status.Enabled {
		return nil
	}

	valid := status.ValidCert && status.ValidChain && status.ValidKey && status.ValidPair
	ch <- prometheus.MustNewConstMetric(c.metrics.tlsCertificateValid, prometheus.GaugeValue, boolToFloat(valid), c.server)

	if status.NotAfter == "" {
		return nil
	}

	expiry, err := time.Parse(time.RFC3339, status.NotAfter)
	if err != nil {
		return fmt.Errorf("parse certificate expiry %q: %w", status.NotAfter, err)
	}

	ch <- prometheus.MustNewConstMetric(c.metrics.tlsCertificateExpiry, prometheus.GaugeValue, float64(expiry.Unix()), c.server)

	return nil
}

func (c *Collector) collectDNSInfo(ch chan<- prometheus.Metric) error {
	info, err := c.client.GetDNSInfo()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.metrics.dnsCacheEnabled, prometheus.GaugeValue, boolToFloat(info.CacheEnabled), c.server)
	ch <- prometheus.MustNewConstMetric(c.metrics.dnsCacheSizeBytes, prometheus.GaugeValue, float64(info.CacheSize), c.server)
	ch <- prometheus.MustNewConstMetric(c.metrics.dnsRatelimit, prometheus.GaugeValue, float64(info.Ratelimit), c.server)
	ch <- prometheus.MustNewConstMetric(c.metrics.dnssecEnabled, prometheus.GaugeValue, boolToFloat(info.DNSSECEnabled), c.server)

	return nil
}

func boolToFloat(value bool) float64 {
	if value {
		return 1
	}

	return 0
}
