package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/victorjacobs/adguard-exporter/collector"
)

const (
	readHeaderTimeout = 5 * time.Second
	shutdownTimeout   = 10 * time.Second
)

var landingPageTemplate = template.Must(template.New("landing-page").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>AdGuard Exporter</title></head>
<body><h1>AdGuard Exporter</h1><p><a href="{{.}}">Metrics</a></p></body>
</html>`))

func envOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return defaultValue
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
		slog.Error("invalid log level", "level", *logLevel, "err", err)
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	client, err := collector.NewClient(*adguardURL, *adguardUsername, *adguardPassword)
	if err != nil {
		logger.Error("invalid configuration", "err", err)
		os.Exit(2)
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(collector.NewCollector(client, *adguardURL, logger))

	handler, err := newHandler(*metricsPath, registry, logger)
	if err != nil {
		logger.Error("invalid configuration", "err", err)
		os.Exit(2)
	}

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	logger.Info("starting adguard-exporter", "listen", *listenAddr, "path", *metricsPath, "target", *adguardURL)
	if err := serve(server, logger); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

func newHandler(metricsPath string, registry *prometheus.Registry, logger *slog.Logger) (http.Handler, error) {
	if err := validateMetricsPath(metricsPath); err != nil {
		return nil, err
	}

	var landingPage bytes.Buffer
	if err := landingPageTemplate.Execute(&landingPage, metricsPath); err != nil {
		return nil, fmt.Errorf("render landing page: %w", err)
	}
	landingPageContent := landingPage.Bytes()

	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry}))
	mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/" {
			http.NotFound(response, request)

			return
		}

		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := response.Write(landingPageContent); err != nil {
			logger.Debug("failed to write landing page", "err", err)
		}
	})

	return mux, nil
}

func validateMetricsPath(metricsPath string) error {
	if metricsPath == "/" {
		return fmt.Errorf("telemetry path must not be /")
	}
	if !strings.HasPrefix(metricsPath, "/") {
		return fmt.Errorf("telemetry path must start with /")
	}
	if strings.ContainsAny(metricsPath, "{}?# \t\r\n") {
		return fmt.Errorf("telemetry path contains unsupported characters")
	}

	return nil
}

func serve(server *http.Server, logger *slog.Logger) error {
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return err
	case <-signalContext.Done():
		logger.Info("shutting down adguard-exporter")

		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shut down server: %w", err)
		}

		err := <-serverErrors
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return err
	}
}
