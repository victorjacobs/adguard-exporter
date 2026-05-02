# AdGuard Prometheus Exporter - Implementation Plan

## Goal
Create a Prometheus exporter for AdGuard Home DNS server in Go, matching an exact metric schema so existing dashboards can be reused.

## Project Structure
```
adguard-exporter/
├── go.mod
├── go.sum
├── main.go                  # HTTP server, flags/env config, /metrics endpoint
├── collector/
│   ├── collector.go         # Prometheus Collector implementation
│   ├── client.go            # AdGuard Home API client
│   └── types.go             # API response structs
```

## Steps

### Step 1: Initialize Go module [ ]
- `go mod init github.com/victorquispesegura/adguard-exporter`
- Add dependencies: `github.com/prometheus/client_golang`
- `go mod tidy`
- Commit: "chore: initialize Go module"

### Step 2: Implement AdGuard API client [ ]
- File: `collector/client.go` + `collector/types.go`
- Endpoints to call:
  - `GET /control/status` → running, protection_enabled, dhcp_enabled
  - `GET /control/stats` → queries, blocked, avg_processing_time, top domains/clients/upstreams
  - `GET /control/querylog` → per-query details for histograms
- Support Basic Auth (username + password config)
- Configurable AdGuard Home base URL
- Commit: "feat: add AdGuard Home API client"

### Step 3: Implement Prometheus collector [ ]
- File: `collector/collector.go`
- Implements `prometheus.Collector` interface (`Describe` + `Collect`)
- All metrics (see below)
- Handle query/blocked reset-to-zero: use Gauge (not Counter) since the API returns a rolling window
- Commit: "feat: implement Prometheus collector with all metrics"

### Step 4: Create main.go [ ]
- HTTP server on configurable port (default :9617)
- Flags / env vars:
  - `--adguard.url` / `ADGUARD_URL` (default: http://localhost:3000)
  - `--adguard.username` / `ADGUARD_USERNAME`
  - `--adguard.password` / `ADGUARD_PASSWORD`
  - `--web.listen-address` / `WEB_LISTEN_ADDRESS` (default: :9617)
  - `--web.telemetry-path` / `WEB_TELEMETRY_PATH` (default: /metrics)
  - `--log.level` / `LOG_LEVEL` (default: info)
- Register collector, expose `/metrics`
- Commit: "feat: add main HTTP server and configuration"

---

## Metric Schema

### Simple Gauges
| Metric | Labels | Source |
|--------|--------|--------|
| `adguard_running` | `server` | /control/status |
| `adguard_protection_enabled` | `server` | /control/status |
| `adguard_dhcp_enabled` | `server` | /control/status |
| `adguard_avg_processing_time_seconds` | `server` | /control/stats |
| `adguard_queries` | `server` | /control/stats |
| `adguard_queries_blocked` | `server` | /control/stats |
| `adguard_replaced_safebrowsing` | `server` | /control/stats |
| `adguard_replaced_parental` | `server` | /control/stats |
| `adguard_replaced_safesearch` | `server` | /control/stats |

### Histograms
| Metric | Labels | Buckets | Source |
|--------|--------|---------|--------|
| `adguard_processing_time_milliseconds` | `client`, `server`, `upstream` | 0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10,+Inf (ms) | /control/querylog |
| `adguard_processing_time_seconds` | `client`, `server`, `upstream` | 0.000005,0.00001,...,0.01,+Inf (seconds) | /control/querylog |
| `adguard_queries_details_histogram` | `client_name`,`protocol`,`reason`,`server`,`status`,`upstream`,`user` | 0,10,20,30,40,50,60,70,80,90,+Inf (ms) | /control/querylog |

### Labeled Gauges
| Metric | Labels | Source |
|--------|--------|--------|
| `adguard_queries_details` | `client`,`client_name`,`domain`,`protocol`,`reason`,`server`,`status`,`type`,`upstream` | /control/querylog |
| `adguard_query_types` | `server`, `type` | /control/stats |
| `adguard_top_queried_domains` | `domain`, `server` | /control/stats |
| `adguard_top_blocked_domains` | `domain`, `server` | /control/stats |
| `adguard_top_clients` | `client`, `server` | /control/stats |
| `adguard_top_upstreams` | `server`, `upstream` | /control/stats |
| `adguard_top_upstreams_avg_response_time_seconds` | `server`, `upstream` | /control/stats |

### Counter
| Metric | Labels |
|--------|--------|
| `adguard_scrape_errors_total` | `server` |

---

## Key Notes
- `adguard_queries` and `adguard_queries_blocked` use **Gauge** not Counter — the API returns a rolling window that can reset to 0
- `adguard_queries_details` is set per unique combination of all labels (one data point per query log entry)
- Histograms are built from raw query log entries
- The `server` label value = the configured AdGuard Home URL
