package collector

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClientValidatesBaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		baseURL string
		wantErr string
	}{
		{name: "empty", wantErr: "unsupported scheme"},
		{name: "missing scheme", baseURL: "adguard.example", wantErr: "unsupported scheme"},
		{name: "unsupported scheme", baseURL: "ftp://adguard.example", wantErr: "unsupported scheme"},
		{name: "missing host", baseURL: "http:///control", wantErr: "host is required"},
		{name: "query", baseURL: "https://adguard.example?target=other", wantErr: "query and fragment"},
		{name: "fragment", baseURL: "https://adguard.example/#fragment", wantErr: "query and fragment"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewClient(test.baseURL, "", "")
			if err == nil {
				t.Fatal("NewClient() returned no error")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("NewClient() error = %q, want it to contain %q", err, test.wantErr)
			}
		})
	}
}

func TestClientGetQueryLog(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/adguard/control/querylog" {
			t.Errorf("request path = %q, want %q", request.URL.Path, "/adguard/control/querylog")
		}
		if request.URL.Query().Get("limit") != "1000" {
			t.Errorf("limit = %q, want %q", request.URL.Query().Get("limit"), "1000")
		}
		if request.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q, want %q", request.Header.Get("Accept"), "application/json")
		}

		username, password, authenticated := request.BasicAuth()
		if !authenticated || username != "admin" || password != "secret" {
			t.Errorf("basic auth = (%q, %q, %t), want (admin, secret, true)", username, password, authenticated)
		}

		response.Header().Set("Content-Type", "application/json")
		if _, err := response.Write([]byte(`{
			"data": [{
				"client": "192.0.2.1",
				"client_info": {"name": "laptop"},
				"client_proto": "doh",
				"elapsedMs": "1.25",
				"question": {"name": "example.com", "type": "A"},
				"reason": "NotFilteredNotFound",
				"status": "NOERROR",
				"upstream": "https://dns.example/dns-query"
			}]
		}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL+"/adguard/", "admin", "secret")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	queryLog, err := client.GetQueryLog()
	if err != nil {
		t.Fatalf("GetQueryLog() error = %v", err)
	}
	if len(queryLog.Data) != 1 {
		t.Fatalf("GetQueryLog() returned %d entries, want 1", len(queryLog.Data))
	}

	entry := queryLog.Data[0]
	if entry.ClientProtocol != "doh" {
		t.Errorf("ClientProtocol = %q, want %q", entry.ClientProtocol, "doh")
	}
	if entry.ElapsedMs != "1.25" {
		t.Errorf("ElapsedMs = %q, want %q", entry.ElapsedMs, "1.25")
	}
}

func TestClientReportsResponseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    string
	}{
		{name: "unexpected status", statusCode: http.StatusBadGateway, body: "upstream exploded", wantErr: "502 Bad Gateway: upstream exploded"},
		{name: "invalid JSON", statusCode: http.StatusOK, body: "{", wantErr: "decode response from /control/status"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(test.statusCode)
				if _, err := fmt.Fprint(response, test.body); err != nil {
					t.Errorf("write response: %v", err)
				}
			}))
			defer server.Close()

			client, err := NewClient(server.URL, "", "")
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			_, err = client.GetStatus()
			if err == nil {
				t.Fatal("GetStatus() returned no error")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("GetStatus() error = %q, want it to contain %q", err, test.wantErr)
			}
		})
	}
}
