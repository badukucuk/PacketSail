package macosproxy

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseHTTPSSettings(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    HTTPSSettings
		wantErr bool
	}{
		{
			name: "disabled proxy with saved address",
			output: "Enabled: No\n" +
				"Server: 127.0.0.1\n" +
				"Port: 9877\n" +
				"Authenticated Proxy Enabled: 0\n",
			want: HTTPSSettings{
				Enabled:       false,
				Server:        "127.0.0.1",
				Port:          9877,
				Authenticated: false,
			},
		},
		{
			name: "enabled proxy",
			output: "Enabled: Yes\n" +
				"Server: proxy.example.com\n" +
				"Port: 8080\n" +
				"Authenticated Proxy Enabled: 0\n",
			want: HTTPSSettings{
				Enabled: true,
				Server:  "proxy.example.com",
				Port:    8080,
			},
		},
		{
			name: "authenticated proxy",
			output: "Enabled: Yes\n" +
				"Server: proxy.example.com\n" +
				"Port: 443\n" +
				"Authenticated Proxy Enabled: 1\n",
			want: HTTPSSettings{
				Enabled:       true,
				Server:        "proxy.example.com",
				Port:          443,
				Authenticated: true,
			},
		},
		{
			name: "missing required field",
			output: "Enabled: No\n" +
				"Server:\n" +
				"Port: 0\n",
			wantErr: true,
		},
		{
			name: "invalid enabled value",
			output: "Enabled: Maybe\n" +
				"Server: 127.0.0.1\n" +
				"Port: 9877\n" +
				"Authenticated Proxy Enabled: 0\n",
			wantErr: true,
		},
		{
			name: "invalid port",
			output: "Enabled: Yes\n" +
				"Server: proxy.example.com\n" +
				"Port: 70000\n" +
				"Authenticated Proxy Enabled: 0\n",
			wantErr: true,
		},
		{
			name: "duplicate field",
			output: "Enabled: No\n" +
				"Enabled: Yes\n" +
				"Server: 127.0.0.1\n" +
				"Port: 9877\n" +
				"Authenticated Proxy Enabled: 0\n",
			wantErr: true,
		},
		{
			name: "enabled proxy without server",
			output: "Enabled: Yes\n" +
				"Server:\n" +
				"Port: 9877\n" +
				"Authenticated Proxy Enabled: 0\n",
			wantErr: true,
		},
		{
			name:    "unexpected output",
			output:  "networksetup failed\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHTTPSSettings(tt.output)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseHTTPSSettings() error = %v", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf(
					"parseHTTPSSettings() = %+v, want %+v",
					got,
					tt.want,
				)
			}
		})
	}
}

// This integration test reads the user's real network service.
// It is opt-in because service names differ between machines.
func TestReadHTTPSSettings(t *testing.T) {
	service := os.Getenv("PACKETSAIL_TEST_NETWORK_SERVICE")
	if service == "" {
		t.Skip("set PACKETSAIL_TEST_NETWORK_SERVICE to run")
	}

	settings, err := ReadHTTPSSettings(service)
	if err != nil {
		t.Fatalf("ReadHTTPSSettings(%q): %v", service, err)
	}

	t.Logf(
		"service=%q enabled=%t server=%q port=%d authenticated=%t",
		service,
		settings.Enabled,
		settings.Server,
		settings.Port,
		settings.Authenticated,
	)
}

func TestReadHTTPSSettingsRejectsEmptyService(t *testing.T) {
	_, err := ReadHTTPSSettings("   ")

	if err == nil {
		t.Fatal("expected an error for an empty network service")
	}

	if !strings.Contains(err.Error(), "network service name cannot be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Reads the live macOS configuration without changing proxy settings.
func TestCaptureHTTPSProxy(t *testing.T) {
	service := os.Getenv("PACKETSAIL_TEST_NETWORK_SERVICE")
	if service == "" {
		t.Skip("set PACKETSAIL_TEST_NETWORK_SERVICE to run")
	}

	snapshot, err := CaptureHTTPSProxy()
	if err != nil {
		t.Fatalf("CaptureHTTPSProxy() error = %v", err)
	}

	if snapshot.Service != service {
		t.Fatalf(
			"detected service = %q, want %q",
			snapshot.Service,
			service,
		)
	}

	t.Logf(
		"service=%q enabled=%t server=%q port=%d authenticated=%t",
		snapshot.Service,
		snapshot.Settings.Enabled,
		snapshot.Settings.Server,
		snapshot.Settings.Port,
		snapshot.Settings.Authenticated,
	)
}

func TestValidateRestorableSnapshot(t *testing.T) {
	valid := HTTPSProxySnapshot{
		Service: "Wi-Fi",
		Settings: HTTPSSettings{
			Server: "127.0.0.1",
			Port:   9877,
		},
	}

	tests := []struct {
		name    string
		modify  func(*HTTPSProxySnapshot)
		wantErr bool
	}{
		{
			name: "disabled proxy with saved address",
		},
		{
			name: "enabled proxy",
			modify: func(s *HTTPSProxySnapshot) {
				s.Settings.Enabled = true
			},
		},
		{
			name: "empty server",
			modify: func(s *HTTPSProxySnapshot) {
				s.Settings.Server = ""
			},
			wantErr: true,
		},
		{
			name: "zero port",
			modify: func(s *HTTPSProxySnapshot) {
				s.Settings.Port = 0
			},
			wantErr: true,
		},
		{
			name: "port above maximum",
			modify: func(s *HTTPSProxySnapshot) {
				s.Settings.Port = 65536
			},
			wantErr: true,
		},
		{
			name: "authenticated proxy",
			modify: func(s *HTTPSProxySnapshot) {
				s.Settings.Authenticated = true
			},
			wantErr: true,
		},
		{
			name: "missing service",
			modify: func(s *HTTPSProxySnapshot) {
				s.Service = ""
			},
			wantErr: true,
		},
		{
			name: "invalid service prefix",
			modify: func(s *HTTPSProxySnapshot) {
				s.Service = "-invalid"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := valid

			if tt.modify != nil {
				tt.modify(&snapshot)
			}

			err := validateRestorableSnapshot(snapshot)

			if tt.wantErr && err == nil {
				t.Fatal("expected validation error")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateRestorableSnapshotEmptyProxy(t *testing.T) {
	tests := []struct {
		name     string
		settings HTTPSSettings
		wantErr  bool
	}{
		{
			name: "disabled and empty",
			settings: HTTPSSettings{
				Enabled: false,
				Server:  "",
				Port:    0,
			},
		},
		{
			name: "enabled and empty",
			settings: HTTPSSettings{
				Enabled: true,
				Server:  "",
				Port:    0,
			},
			wantErr: true,
		},
		{
			name: "disabled with missing server",
			settings: HTTPSSettings{
				Enabled: false,
				Server:  "",
				Port:    8080,
			},
			wantErr: true,
		},
		{
			name: "disabled with missing port",
			settings: HTTPSSettings{
				Enabled: false,
				Server:  "proxy.example.com",
				Port:    0,
			},
			wantErr: true,
		},
		{
			name: "disabled with previous settings",
			settings: HTTPSSettings{
				Enabled: false,
				Server:  "proxy.example.com",
				Port:    8080,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := HTTPSProxySnapshot{
				Service:  "Wi-Fi",
				Settings: tt.settings,
			}

			err := validateRestorableSnapshot(snapshot)

			if (err != nil) != tt.wantErr {
				t.Fatalf(
					"validateRestorableSnapshot() error = %v, wantErr = %t",
					err,
					tt.wantErr,
				)
			}
		})
	}
}
