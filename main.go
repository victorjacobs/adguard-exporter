package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/victorquispesegura/adguard-exporter/collector"
)

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	adguardURL := flag.String("adguard.url", envOrDefault("ADGUARD_URL", "http://localhost:3000"), "AdGuard Home base URL")
	adguardUsername := flag.String("adguard.username", envOrDefault("ADGUARD_USERNAME", ""), "AdGuard Home username")
	adguardPassword := flag.String("adguard.password", envOrDefault("ADGUARD_PASSWORD", ""), "AdGuard Home password")
	listenAddr := flag.String("web.listen-address", envOrDefault("WEB_LISTEN_ADDRESS", ":9617"), "Address to listen on for telemetry")
	metricsPath := flag.String("web.telemetry-path", envOrDefault("WEB_TELEMETRY_PATH", "/metrics"), "Path under which to expose metrics")
	logLevel := flag.String("log.level", envOrDefault("LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	client := collector.NewClient(*adguardURL, *adguardUsername, *adguardPassword)
	col := collector.NewCollector(client, *adguardURL, logger)

	reg := prometheus.NewRegistry()
	reg.MustRegister(col)

	http.Handle(*metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>AdGuard Exporter</title></head><body>
<h1>AdGuard Exporter</h1><p><a href="` + *metricsPath + `">Metrics</a></p></body></html>`))
	})

	logger.Info("starting adguard-exporter", "listen", *listenAddr, "path", *metricsPath, "target", *adguardURL)
	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}
