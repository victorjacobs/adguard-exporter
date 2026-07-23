package collector

// StatusResponse represents the /control/status API response.
type StatusResponse struct {
	Running           bool     `json:"running"`
	ProtectionEnabled bool     `json:"protection_enabled"`
	DNSAddresses      []string `json:"dns_addresses"`
	DNSPort           int      `json:"dns_port"`
	HTTPPort          int      `json:"http_port"`
}

// DHCPStatusResponse represents the /control/dhcp/status API response.
type DHCPStatusResponse struct {
	Enabled bool `json:"enabled"`
}

// StatsResponse represents the /control/stats API response.
type StatsResponse struct {
	NumDNSQueries           int                  `json:"num_dns_queries"`
	NumBlockedFiltering     int                  `json:"num_blocked_filtering"`
	NumReplacedSafebrowsing int                  `json:"num_replaced_safebrowsing"`
	NumReplacedParental     int                  `json:"num_replaced_parental"`
	NumReplacedSafesearch   int                  `json:"num_replaced_safesearch"`
	AvgProcessingTime       float64              `json:"avg_processing_time"`
	TopQueriedDomains       []map[string]int     `json:"top_queried_domains"`
	TopBlockedDomains       []map[string]int     `json:"top_blocked_domains"`
	TopClients              []map[string]int     `json:"top_clients"`
	TopUpstreamsResponses   []map[string]int     `json:"top_upstreams_responses"`
	TopUpstreamsAvgTime     []map[string]float64 `json:"top_upstreams_avg_time"`
	QueryTypes              map[string]float64   `json:"query_types"`
}

// QueryLogResponse represents the /control/querylog API response.
type QueryLogResponse struct {
	Data   []QueryLogEntry `json:"data"`
	Oldest string          `json:"oldest"`
}

// QueryLogEntry represents a single entry in the query log.
type QueryLogEntry struct {
	Question       Question   `json:"question"`
	Answer         []Answer   `json:"answer,omitempty"`
	Client         string     `json:"client"`
	ClientInfo     ClientInfo `json:"client_info,omitempty"`
	ClientProtocol string     `json:"client_proto,omitempty"`
	Upstream       string     `json:"upstream"`
	ElapsedMs      string     `json:"elapsedMs,omitempty"`
	Time           string     `json:"time"`
	Reason         string     `json:"reason"`
	Status         string     `json:"status,omitempty"`
	FilterID       int64      `json:"filterId,omitempty"`
	Rule           string     `json:"rule,omitempty"`
	ServiceName    string     `json:"service_name,omitempty"`
}

// FilteringStatusResponse represents the /control/filtering/status API response.
type FilteringStatusResponse struct {
	Enabled          bool     `json:"enabled"`
	Interval         int      `json:"interval"`
	Filters          []Filter `json:"filters"`
	WhitelistFilters []Filter `json:"whitelist_filters"`
	UserRules        []string `json:"user_rules"`
}

// Filter represents a single filter list.
type Filter struct {
	Enabled     bool   `json:"enabled"`
	ID          int64  `json:"id"`
	LastUpdated string `json:"last_updated"`
	Name        string `json:"name"`
	RulesCount  int    `json:"rules_count"`
	URL         string `json:"url"`
}

// TLSStatusResponse represents the /control/tls/status API response.
type TLSStatusResponse struct {
	Enabled    bool   `json:"enabled"`
	ValidCert  bool   `json:"valid_cert"`
	ValidChain bool   `json:"valid_chain"`
	ValidKey   bool   `json:"valid_key"`
	ValidPair  bool   `json:"valid_pair"`
	NotAfter   string `json:"not_after"`
	NotBefore  string `json:"not_before"`
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
}

// DNSInfoResponse represents the /control/dns_info API response.
type DNSInfoResponse struct {
	CacheEnabled    bool `json:"cache_enabled"`
	CacheSize       int  `json:"cache_size"`
	CacheOptimistic bool `json:"cache_optimistic"`
	Ratelimit       int  `json:"ratelimit"`
	DNSSECEnabled   bool `json:"dnssec_enabled"`
	DisableIPv6     bool `json:"disable_ipv6"`
}

// Question represents the DNS question in a query log entry.
type Question struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Class string `json:"class"`
}

type ClientInfo struct {
	Name string `json:"name"`
}

// Answer represents a DNS answer in a query log entry.
type Answer struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}
