package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLookupIPv4Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected HTTP method: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if r.URL.Query().Get("name") != "example.com" {
			t.Errorf("unexpected hostname: %s", r.URL.Query().Get("name"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.URL.Query().Get("type") != "A" {
			t.Errorf("unexpected DNS record type: %s", r.URL.Query().Get("type"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		fmt.Fprint(w, `{
            "Status": 0,
            "Answer": [
                {"type": 1, "data": "192.0.2.10"},
                {"type": 5, "data": "alias.example.com"}
            ]
        }`)
	}))
	defer server.Close()

	resolver := &Resolver{
		client:   server.Client(),
		endpoint: server.URL,
	}

	addresses, err := resolver.LookupIPv4(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup IPv4: %v", err)
	}

	if len(addresses) != 1 {
		t.Fatalf("unexpected address count: got %d, want 1", len(addresses))
	}

	expected := net.ParseIP("192.0.2.10")
	if !addresses[0].Equal(expected) {
		t.Fatalf("unexpected IP: got %s, want %s", addresses[0], expected)
	}
}

func TestLookupIPv4Errors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantError  string
	}{
		{
			name:       "HTTP server failure",
			statusCode: http.StatusServiceUnavailable,
			response:   "service unavailable",
			wantError:  "HTTP status 503",
		},
		{
			name:       "DNS name not found",
			statusCode: http.StatusOK,
			response:   `{"Status": 3}`,
			wantError:  "response code 3",
		},
		{
			name:       "invalid JSON",
			statusCode: http.StatusOK,
			response:   `{"Status":`,
			wantError:  "decode DNS response",
		},
		{
			name:       "no IPv4 answers",
			statusCode: http.StatusOK,
			response:   `{"Status": 0, "Answer": []}`,
			wantError:  "no IPv4 addresses found",
		},
		{
			name:       "truncated DNS response",
			statusCode: http.StatusOK,
			response:   `{"Status": 0, "TC": true}`,
			wantError:  "DNS response was truncated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				fmt.Fprint(w, tt.response)
			}))
			defer server.Close()

			resolver := &Resolver{
				client:   server.Client(),
				endpoint: server.URL,
			}

			_, err := resolver.LookupIPv4(context.Background(), "example.com")
			if err == nil {
				t.Fatal("expected DNS lookup to fail")
			}

			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("unexpected error: got %q, want substring %q",
					err.Error(), tt.wantError)
			}
		})
	}
}

func TestLookupIPv4Canceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resolver := NewResolver()

	_, err := resolver.LookupIPv4(ctx, "example.com")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestLiveDoH(t *testing.T) {
	if os.Getenv("PACKETSAIL_TEST_LIVE_DOH") != "1" {
		t.Skip("live DNS test is disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resolver := NewResolver()

	addresses, err := resolver.LookupIPv4(ctx, "example.com")
	if err != nil {
		t.Fatalf("live DNS lookup failed: %v", err)
	}

	if len(addresses) == 0 {
		t.Fatal("live DNS lookup returned no IPv4 addresses")
	}

	for _, ip := range addresses {
		if ip.To4() == nil {
			t.Fatalf("DNS response contains a non-IPv4 address: %s", ip)
		}
	}

	t.Logf("resolved example.com to %v", addresses)
}
