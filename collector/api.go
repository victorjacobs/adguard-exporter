package collector

type APIClient interface {
	GetStatus() (*StatusResponse, error)
	GetDHCPStatus() (*DHCPStatusResponse, error)
	GetStats() (*StatsResponse, error)
	GetQueryLog() (*QueryLogResponse, error)
	GetFilteringStatus() (*FilteringStatusResponse, error)
	GetTLSStatus() (*TLSStatusResponse, error)
	GetDNSInfo() (*DNSInfoResponse, error)
}
