package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("ADGUARD_EXPORTER_TEST_VALUE", "")
	if got := envOrDefault("ADGUARD_EXPORTER_TEST_VALUE", "default"); got != "default" {
		t.Errorf("envOrDefault() = %q, want %q", got, "default")
	}

	t.Setenv("ADGUARD_EXPORTER_TEST_VALUE", "configured")
	if got := envOrDefault("ADGUARD_EXPORTER_TEST_VALUE", "default"); got != "configured" {
		t.Errorf("envOrDefault() = %q, want %q", got, "configured")
	}
}

func TestValidateMetricsPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "default", path: "/metrics"},
		{name: "nested", path: "/prometheus/metrics"},
		{name: "root", path: "/", wantErr: true},
		{name: "relative", path: "metrics", wantErr: true},
		{name: "wildcard", path: "/metrics/{name}", wantErr: true},
		{name: "query", path: "/metrics?format=openmetrics", wantErr: true},
		{name: "space", path: "/custom metrics", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateMetricsPath(test.path)
			if test.wantErr && err == nil {
				t.Fatalf("validateMetricsPath(%q) returned no error", test.path)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("validateMetricsPath(%q) error = %v", test.path, err)
			}
		})
	}
}

func TestHandlerRoutes(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := newHandler("/custom-metrics", prometheus.NewRegistry(), logger)
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}

	tests := []struct {
		name            string
		path            string
		wantStatus      int
		wantContentType string
		wantBody        string
	}{
		{
			name:            "landing page",
			path:            "/",
			wantStatus:      http.StatusOK,
			wantContentType: "text/html; charset=utf-8",
			wantBody:        `href="/custom-metrics"`,
		},
		{
			name:            "metrics",
			path:            "/custom-metrics",
			wantStatus:      http.StatusOK,
			wantContentType: "text/plain",
		},
		{
			name:       "not found",
			path:       "/missing",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Errorf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if test.wantContentType != "" && !strings.HasPrefix(response.Header().Get("Content-Type"), test.wantContentType) {
				t.Errorf("Content-Type = %q, want prefix %q", response.Header().Get("Content-Type"), test.wantContentType)
			}
			if test.wantBody != "" && !strings.Contains(response.Body.String(), test.wantBody) {
				t.Errorf("body = %q, want it to contain %q", response.Body.String(), test.wantBody)
			}
		})
	}
}
