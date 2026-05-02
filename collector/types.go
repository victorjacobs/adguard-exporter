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
	NumDNSQueries           int                    `json:"num_dns_queries"`
	NumBlockedFiltering     int                    `json:"num_blocked_filtering"`
	NumReplacedSafebrowsing int                    `json:"num_replaced_safebrowsing"`
	NumReplacedParental     int                    `json:"num_replaced_parental"`
	NumReplacedSafesearch   int                    `json:"num_replaced_safesearch"`
	AvgProcessingTime       float64                `json:"avg_processing_time"`
	TopQueriedDomains       []map[string]int       `json:"top_queried_domains"`
	TopBlockedDomains       []map[string]int       `json:"top_blocked_domains"`
	TopClients              []map[string]int       `json:"top_clients"`
	TopUpstreamsResponses   []map[string]int       `json:"top_upstreams_responses"`
	TopUpstreamsAvgTime     []map[string]float64   `json:"top_upstreams_avg_time"`
	QueryTypes              map[string]float64     `json:"query_types"`
}

// QueryLogResponse represents the /control/querylog API response.
type QueryLogResponse struct {
	Data   []QueryLogEntry `json:"data"`
	Oldest string          `json:"oldest"`
}

// QueryLogEntry represents a single entry in the query log.
type QueryLogEntry struct {
	Question   Question `json:"question"`
	Answer     []Answer `json:"answer,omitempty"`
	Client     string   `json:"client"`
	ClientName string   `json:"client_info,omitempty"`
	Upstream   string   `json:"upstream"`
	ElapsedMs  float64  `json:"elapsedMs,omitempty"`
	Time       string   `json:"time"`
	Reason     string   `json:"reason"`
	Status     string   `json:"status,omitempty"`
	FilterID   int64    `json:"filter_id,omitempty"`
	Rule       string   `json:"rule,omitempty"`
	ServiceName string  `json:"service_name,omitempty"`
}

// Question represents the DNS question in a query log entry.
type Question struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Class string `json:"class"`
}

// Answer represents a DNS answer in a query log entry.
type Answer struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}
