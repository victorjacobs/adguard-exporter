package collector

import "github.com/prometheus/client_golang/prometheus"

const metricNamespace = "adguard"

type metricDescriptors struct {
	running                     *prometheus.Desc
	protectionEnabled           *prometheus.Desc
	dhcpEnabled                 *prometheus.Desc
	avgProcessingTime           *prometheus.Desc
	queries                     *prometheus.Desc
	queriesBlocked              *prometheus.Desc
	replacedSafebrowsing        *prometheus.Desc
	replacedParental            *prometheus.Desc
	replacedSafesearch          *prometheus.Desc
	queriesDetails              *prometheus.Desc
	queryTypes                  *prometheus.Desc
	topQueriedDomains           *prometheus.Desc
	topBlockedDomains           *prometheus.Desc
	topClients                  *prometheus.Desc
	topUpstreams                *prometheus.Desc
	topUpstreamsAvgResponseTime *prometheus.Desc
	processingTimeMilliseconds  *prometheus.Desc
	processingTimeSeconds       *prometheus.Desc
	queriesDetailsHistogram     *prometheus.Desc
	filteringEnabled            *prometheus.Desc
	filterRulesCount            *prometheus.Desc
	userRulesCount              *prometheus.Desc
	tlsEnabled                  *prometheus.Desc
	tlsCertificateExpiry        *prometheus.Desc
	tlsCertificateValid         *prometheus.Desc
	dnsCacheEnabled             *prometheus.Desc
	dnsCacheSizeBytes           *prometheus.Desc
	dnsRatelimit                *prometheus.Desc
	dnssecEnabled               *prometheus.Desc
}

func newMetricDescriptors() metricDescriptors {
	return metricDescriptors{
		running:                     newMetricDesc("running", "Whether AdGuard Home is running (1 = running, 0 = not running).", "server"),
		protectionEnabled:           newMetricDesc("protection_enabled", "Whether DNS protection is enabled (1 = enabled, 0 = disabled).", "server"),
		dhcpEnabled:                 newMetricDesc("dhcp_enabled", "Whether the DHCP server is enabled (1 = enabled, 0 = disabled).", "server"),
		avgProcessingTime:           newMetricDesc("avg_processing_time_seconds", "Average DNS query processing time in seconds.", "server"),
		queries:                     newMetricDesc("queries", "Monotonic DNS query count synthesized from AdGuard Home's rolling statistics.", "server"),
		queriesBlocked:              newMetricDesc("queries_blocked", "Monotonic blocked DNS query count synthesized from AdGuard Home's rolling statistics.", "server"),
		replacedSafebrowsing:        newMetricDesc("replaced_safebrowsing", "Queries replaced by safe browsing in AdGuard Home's configured statistics window.", "server"),
		replacedParental:            newMetricDesc("replaced_parental", "Queries replaced by parental control in AdGuard Home's configured statistics window.", "server"),
		replacedSafesearch:          newMetricDesc("replaced_safesearch", "Queries replaced by safe search in AdGuard Home's configured statistics window.", "server"),
		queriesDetails:              newMetricDesc("queries_details", "Number of DNS queries with a detailed label breakdown.", "client", "client_name", "domain", "protocol", "reason", "server", "status", "type", "upstream"),
		queryTypes:                  newMetricDesc("query_types", "Number of DNS queries by type.", "server", "type"),
		topQueriedDomains:           newMetricDesc("top_queried_domains", "Queries for each top queried domain.", "server", "domain"),
		topBlockedDomains:           newMetricDesc("top_blocked_domains", "Queries for each top blocked domain.", "server", "domain"),
		topClients:                  newMetricDesc("top_clients", "Monotonic DNS query count synthesized for each top client.", "server", "client"),
		topUpstreams:                newMetricDesc("top_upstreams", "Responses from each top upstream DNS server.", "server", "upstream"),
		topUpstreamsAvgResponseTime: newMetricDesc("top_upstreams_avg_response_time_seconds", "Average response time of each top upstream DNS server in seconds.", "server", "upstream"),
		processingTimeMilliseconds:  newMetricDesc("processing_time_milliseconds", "Histogram of DNS query processing time in milliseconds.", "client", "server", "upstream"),
		processingTimeSeconds:       newMetricDesc("processing_time_seconds", "Histogram of DNS query processing time in seconds.", "client", "server", "upstream"),
		queriesDetailsHistogram:     newMetricDesc("queries_details_histogram", "Histogram of DNS queries with a detailed label breakdown by processing time in milliseconds.", "client_name", "protocol", "reason", "server", "status", "upstream", "user"),
		filteringEnabled:            newMetricDesc("filtering_enabled", "Whether DNS filtering is enabled (1 = enabled, 0 = disabled).", "server"),
		filterRulesCount:            newMetricDesc("filter_rules_count", "Number of rules in a filter list.", "server", "id", "name", "url"),
		userRulesCount:              newMetricDesc("user_rules_count", "Number of user-defined filtering rules.", "server"),
		tlsEnabled:                  newMetricDesc("tls_enabled", "Whether TLS is enabled (1 = enabled, 0 = disabled).", "server"),
		tlsCertificateExpiry:        newMetricDesc("tls_certificate_expiry_seconds", "Unix timestamp when the TLS certificate expires.", "server"),
		tlsCertificateValid:         newMetricDesc("tls_certificate_valid", "Whether the TLS certificate, chain, key, and pair are valid (1 = valid, 0 = invalid).", "server"),
		dnsCacheEnabled:             newMetricDesc("dns_cache_enabled", "Whether DNS caching is enabled (1 = enabled, 0 = disabled).", "server"),
		dnsCacheSizeBytes:           newMetricDesc("dns_cache_size_bytes", "Configured DNS cache size in bytes.", "server"),
		dnsRatelimit:                newMetricDesc("dns_ratelimit", "Configured DNS rate limit in requests per second (0 = unlimited).", "server"),
		dnssecEnabled:               newMetricDesc("dns_dnssec_enabled", "Whether DNSSEC is enabled (1 = enabled, 0 = disabled).", "server"),
	}
}

func newMetricDesc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(prometheus.BuildFQName(metricNamespace, "", name), help, labels, nil)
}

func (d metricDescriptors) describe(ch chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{
		d.running,
		d.protectionEnabled,
		d.dhcpEnabled,
		d.avgProcessingTime,
		d.queries,
		d.queriesBlocked,
		d.replacedSafebrowsing,
		d.replacedParental,
		d.replacedSafesearch,
		d.queriesDetails,
		d.queryTypes,
		d.topQueriedDomains,
		d.topBlockedDomains,
		d.topClients,
		d.topUpstreams,
		d.topUpstreamsAvgResponseTime,
		d.processingTimeMilliseconds,
		d.processingTimeSeconds,
		d.queriesDetailsHistogram,
		d.filteringEnabled,
		d.filterRulesCount,
		d.userRulesCount,
		d.tlsEnabled,
		d.tlsCertificateExpiry,
		d.tlsCertificateValid,
		d.dnsCacheEnabled,
		d.dnsCacheSizeBytes,
		d.dnsRatelimit,
		d.dnssecEnabled,
	} {
		ch <- descriptor
	}
}
