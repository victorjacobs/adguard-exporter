# CLAUDE.md

## Build & run

Go is provided via a nix flake + direnv. Always activate the environment before running Go commands:

```sh
eval "$(direnv export zsh)"
go build ./...
go vet ./...
```

## Project structure

```
main.go               # HTTP server, flag/env config, /metrics endpoint
collector/
  client.go           # AdGuard Home HTTP API client (Basic Auth)
  types.go            # API response structs
  collector.go        # prometheus.Collector implementation
```

## Key design decisions

**Module:** `github.com/victorjacobs/adguard-exporter`

**Port:** `:9617`

**AdGuard API endpoints used:**
- `GET /control/status` → running, protection_enabled
- `GET /control/dhcp/status` → dhcp_enabled
- `GET /control/stats` → query counts, top domains/clients/upstreams
- `GET /control/querylog?limit=1000` → histograms and per-query details

**Rolling-window reset handling:** `adguard_queries` and `adguard_queries_blocked` come from an API that resets at the top of each hour. The `rollingCounter` type in `collector.go` detects resets (new value < last value) and maintains a monotonically increasing cumulative total so `rate()` works without hourly spikes.

**Histograms are built from raw query log entries** — not from the stats API. Three histogram metrics are emitted per scrape: `adguard_processing_time_milliseconds`, `adguard_processing_time_seconds`, and `adguard_queries_details_histogram`.

**DHCP failures are non-fatal** — if `/control/dhcp/status` fails, `adguard_dhcp_enabled` is emitted as 0 with a warning log rather than failing the whole scrape.

## Commit style

Conventional commits (`feat:`, `fix:`, `chore:`, `docs:`). Commit after each logical step. Do not push (no remote configured).
