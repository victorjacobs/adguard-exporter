# adguard-exporter

Prometheus exporter for [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome).

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `adguard_running` | Gauge | Whether AdGuard Home is running |
| `adguard_protection_enabled` | Gauge | Whether DNS protection is enabled |
| `adguard_dhcp_enabled` | Gauge | Whether the DHCP server is enabled |
| `adguard_avg_processing_time_seconds` | Gauge | Average DNS query processing time |
| `adguard_queries` | Gauge | Cumulative DNS queries processed (reset-aware) |
| `adguard_queries_blocked` | Gauge | Cumulative DNS queries blocked (reset-aware) |
| `adguard_replaced_safebrowsing` | Gauge | Queries replaced by safe browsing |
| `adguard_replaced_parental` | Gauge | Queries replaced by parental control |
| `adguard_replaced_safesearch` | Gauge | Queries replaced by safe search |
| `adguard_queries_details` | Gauge | Per-query breakdown with full label set |
| `adguard_query_types` | Gauge | Query counts by DNS record type |
| `adguard_top_queried_domains` | Gauge | Top queried domains |
| `adguard_top_blocked_domains` | Gauge | Top blocked domains |
| `adguard_top_clients` | Gauge | Top clients by query count |
| `adguard_top_upstreams` | Gauge | Top upstream resolvers by query count |
| `adguard_top_upstreams_avg_response_time_seconds` | Gauge | Average response time per upstream |
| `adguard_processing_time_milliseconds` | Histogram | Query processing time in milliseconds |
| `adguard_processing_time_seconds` | Histogram | Query processing time in seconds |
| `adguard_queries_details_histogram` | Histogram | Processing time histogram with full label set |
| `adguard_scrape_errors_total` | Counter | Total scrape errors |

> **Note on `adguard_queries` / `adguard_queries_blocked`:** AdGuard's stats API returns a rolling window that resets at the top of each hour. The exporter detects these resets and maintains a monotonically increasing cumulative total, so `rate()` works correctly without hourly spikes.

## Configuration

All options can be set via flags or environment variables.

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--adguard.url` | `ADGUARD_URL` | `http://localhost:3000` | AdGuard Home base URL |
| `--adguard.username` | `ADGUARD_USERNAME` | _(none)_ | Basic auth username |
| `--adguard.password` | `ADGUARD_PASSWORD` | _(none)_ | Basic auth password |
| `--web.listen-address` | `WEB_LISTEN_ADDRESS` | `:9617` | Address to expose metrics on |
| `--web.telemetry-path` | `WEB_TELEMETRY_PATH` | `/metrics` | Path to expose metrics on |
| `--log.level` | `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

## Usage

```sh
go build -o adguard-exporter .
./adguard-exporter \
  --adguard.url http://adguard.local:3000 \
  --adguard.username admin \
  --adguard.password secret
```

### Docker

```sh
docker run -p 9617:9617 \
  -e ADGUARD_URL=http://adguard.local:3000 \
  -e ADGUARD_USERNAME=admin \
  -e ADGUARD_PASSWORD=secret \
  ghcr.io/victorjacobs/adguard-exporter
```

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: adguard
    static_configs:
      - targets: ['localhost:9617']
```
