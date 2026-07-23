# CLAUDE.md

## Build & run

Go is provided via a nix flake + direnv. Always activate the environment before running Go commands:

```sh
eval "$(direnv export zsh)"
go build ./...
go test ./...
go vet ./...
staticcheck ./...
```

## Project structure

```
main.go               # HTTP server, flag/env config, /metrics endpoint
collector/
  api.go              # API interface used by the collector
  client.go           # AdGuard Home HTTP API client (Basic Auth)
  collector.go        # prometheus.Collector and statistics metrics
  descriptors.go      # Prometheus metric descriptors
  querylog.go         # query-log metrics and histogram aggregation
  rolling_counter.go  # Monotonic values synthesized from rolling statistics
  types.go            # API response structs
```

## Key design decisions

**Module:** `github.com/victorjacobs/adguard-exporter`

**Port:** `:9617`

**AdGuard API endpoints used:**
- `GET /control/status` → running, protection_enabled
- `GET /control/dhcp/status` → dhcp_enabled
- `GET /control/stats` → query counts, top domains/clients/upstreams
- `GET /control/querylog?limit=1000` → histograms and per-query details
- `GET /control/filtering/status` → filtering and filter-list metrics
- `GET /control/tls/status` → TLS and certificate metrics
- `GET /control/dns_info` → DNS cache, rate-limit, and DNSSEC metrics

**Statistics values come from a rolling window.** `adguard_queries`,
`adguard_queries_blocked`, and `adguard_top_clients` accumulate observed
increases and ignore decreases so they remain monotonic until the exporter
restarts. Other statistics gauges can decrease when old data leaves the window.

**Histograms are built from raw query log entries** — not from the stats API. Three histogram metrics are emitted per scrape: `adguard_processing_time_milliseconds`, `adguard_processing_time_seconds`, and `adguard_queries_details_histogram`.

**Endpoints are collected concurrently and fail independently.** A failed
endpoint omits its metrics and increments `adguard_scrape_errors_total`; metrics
from healthy endpoints are still emitted.

## Commit style

Use conventional commits (`feat:`, `fix:`, `chore:`, `docs:`). Do not commit or
push unless explicitly asked.
